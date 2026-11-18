'use strict';

/**
 * P2P Uzak Masaüstü - Sinyal (Signaling) Sunucusu
 * ---------------------------------------------------------------------------
 * Makineye özel SABİT 9 haneli ID tabanlı oturum modeli.
 *
 *   hosts    : Map<machineId, WebSocket>          -> kayıtlı (online) makineler
 *   pending  : Map<sessionId, {...}>              -> onay bekleyen bağlantılar
 *   sessions : Map<sessionId, {host, viewer}>     -> kurulmuş eşleşmeler
 *
 * Akış:
 *   1) Host (tarayıcı/ajan)  : register-host { machineId }
 *   2) Viewer                : connect { targetId, secret }
 *   3) Sunucu -> host        : connection-request { from, secret }
 *   4) Host -> sunucu        : connection-response { to, accepted }
 *   5) Sunucu -> viewer      : connection-result { accepted }
 *   6) SDP/ICE/anahtar       : signal { data }  (iki yön, uçtan uca şifreli)
 *
 * Güvenlik:
 *   - Origin allowlist (CORS)
 *   - IP başına connect deneme hız sınırı
 *   - Maksimum mesaj / sinyal boyutu
 *   - Host kapasitesi, onay zaman aşımı, oturum TTL
 *   - Ping/pong heartbeat ile kopan bağlantı temizliği
 *   - Sunucu şifreleri SAKLAMAZ; doğrulama host tarafında yapılır.
 */

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Virgülle ayrılmış origin allowlist. '*' tümüne izin verir.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const HEARTBEAT_INTERVAL = 30000;
const MAX_HOSTS = parseInt(process.env.MAX_HOSTS || '500', 10);
const MAX_MESSAGE_BYTES = 256 * 1024; // 256 KB
const MAX_SIGNAL_BYTES = 128 * 1024;  // SDP/ICE için üst sınır
const MAX_SECRET_LEN = 128;

// Bağlantı denemesi hız sınırı (brute-force koruması)
const CONNECT_WINDOW_MS = 60000;
const MAX_CONNECT_ATTEMPTS = 15;
const rateLimits = new Map(); // ip -> { count, resetAt }

// Onay bekleyen istek zaman aşımı
const REQUEST_TIMEOUT_MS = 60000;
// Oturum üst sınırı (bir host için eşzamanlı viewer)
const SESSION_TTL_MS = 12 * 60 * 60000; // 12 saat

// --- Yardımcılar ----------------------------------------------------------
function isOriginAllowed(origin) {
  if (ALLOWED_ORIGINS.includes('*')) return true;
  if (!origin) return true; // curl / UptimeRobot / yerel istemci
  return ALLOWED_ORIGINS.includes(origin);
}

function applyCors(res, origin) {
  const allowAll = ALLOWED_ORIGINS.includes('*');
  res.setHeader('Access-Control-Allow-Origin', allowAll ? '*' : origin || '');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function withinRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimits.set(ip, { count: 1, resetAt: now + CONNECT_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= MAX_CONNECT_ATTEMPTS;
}

function newSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function normalizeMachineId(value) {
  const id = String(value || '').replace(/[^0-9]/g, '');
  if (id.length !== 9) return null;
  return id;
}

function send(ws, payload) {
  if (ws && ws.readyState === ws.OPEN) {
    try {
      ws.send(JSON.stringify(payload));
    } catch (e) { /* yok say */ }
  }
}

function sendError(ws, code, message) {
  send(ws, { type: 'error', code: code, message: message });
}

// --- HTTP katmanı (health check) ------------------------------------------
const server = http.createServer((req, res) => {
  const origin = req.headers.origin;
  applyCors(res, origin);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const path = (req.url || '/').split('?')[0];

  if (req.method === 'GET' && (path === '/' || path === '/health')) {
    const body = JSON.stringify({
      status: 'ok',
      uptime: process.uptime(),
      hosts: hosts.size,
      sessions: sessions.size,
      pending: pending.size,
    });
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(body);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ status: 'error', message: 'Not Found' }));
});

// --- WebSocket katmanı ----------------------------------------------------
const wss = new WebSocketServer({
  server,
  maxPayload: MAX_MESSAGE_BYTES,
  verifyClient: (info, done) => {
    const origin = info.origin || (info.req.headers && info.req.headers.origin);
    if (isOriginAllowed(origin)) return done(true);
    return done(false, 403, 'Forbidden');
  },
});

const hosts = new Map();    // machineId -> WebSocket
const pending = new Map();  // sessionId -> { hostWs, viewerWs, timer }
const sessions = new Map(); // sessionId -> { hostWs, viewerWs, timer }

// --- Oturum yardımcıları --------------------------------------------------
function destroySession(sessionId, reason) {
  const s = sessions.get(sessionId);
  if (!s) return;
  if (s.timer) clearTimeout(s.timer);
  sessions.delete(sessionId);
  if (s.hostWs) s.hostWs.sessionId = null;
  if (s.viewerWs) s.viewerWs.sessionId = null;
  send(s.hostWs, { type: 'peer-left', message: reason || 'Oturum kapandı.' });
  send(s.viewerWs, { type: 'peer-left', message: reason || 'Oturum kapandı.' });
}

function clearPending(sessionId) {
  const p = pending.get(sessionId);
  if (!p) return;
  if (p.timer) clearTimeout(p.timer);
  pending.delete(sessionId);
}

// Bir host yalnızca tek aktif oturuma sahip olabilir.
function attachSession(sessionId, hostWs, viewerWs) {
  if (hostWs.sessionId && sessions.has(hostWs.sessionId)) {
    destroySession(hostWs.sessionId, 'Yeni bir bağlantı kuruldu.');
  }
  const timer = setTimeout(() => destroySession(sessionId, 'Oturum süresi doldu.'), SESSION_TTL_MS);
  if (timer.unref) timer.unref();
  sessions.set(sessionId, { hostWs: hostWs, viewerWs: viewerWs, timer: timer });
  hostWs.sessionId = sessionId;
  viewerWs.sessionId = sessionId;
}

// --- Mesaj işleme ---------------------------------------------------------
function handleMessage(ws, msg) {
  switch (msg.type) {
    case 'ping':
      return send(ws, { type: 'pong', t: msg.t });

    // 1) HOST KAYDI -------------------------------------------------------
    case 'register-host': {
      const machineId = normalizeMachineId(msg.machineId);
      if (!machineId) {
        return sendError(ws, 'BAD_MACHINE_ID', 'Geçersiz makine ID (9 hane olmalı).');
      }
      if (!hosts.has(machineId) && hosts.size >= MAX_HOSTS) {
        return sendError(ws, 'SERVER_FULL', 'Sunucu kapasitesi dolu, sonra tekrar deneyin.');
      }

      const previous = hosts.get(machineId);
      if (previous && previous !== ws) {
        // Aynı ID ile yeniden bağlanan istemci: eski soket geçersiz kılınır.
        previous.replaced = true;
        try { previous.close(4000, 'replaced'); } catch (e) {}
        if (previous.sessionId) destroySession(previous.sessionId, 'Host yeniden bağlandı.');
      }

      ws.role = 'host';
      ws.machineId = machineId;
      ws.hasPassword = !!msg.hasPassword;
      ws.label = typeof msg.label === 'string' ? msg.label.slice(0, 64) : '';
      ws.registeredAt = Date.now();
      hosts.set(machineId, ws);

      return send(ws, { type: 'host-registered', machineId: machineId });
    }

    // 2) VIEWER BAĞLANTI İSTEĞİ -------------------------------------------
    case 'connect': {
      const ip = ws.clientIp || 'unknown';
      if (!withinRateLimit(ip)) {
        return sendError(ws, 'RATE_LIMITED', 'Çok fazla deneme yaptınız. Lütfen bekleyin.');
      }

      const targetId = normalizeMachineId(msg.targetId);
      if (!targetId) {
        return sendError(ws, 'BAD_MACHINE_ID', 'Hedef makine ID geçersiz (9 hane olmalı).');
      }

      const secret = typeof msg.secret === 'string' ? msg.secret : '';
      if (secret.length > MAX_SECRET_LEN) {
        return sendError(ws, 'BAD_SECRET', 'Şifre/PIN çok uzun.');
      }

      const hostWs = hosts.get(targetId);
      if (!hostWs || hostWs.readyState !== hostWs.OPEN) {
        return sendError(ws, 'HOST_OFFLINE', 'Bu ID için çevrimiçi makine bulunamadı.');
      }
      if (ws.sessionId && sessions.has(ws.sessionId)) {
        return sendError(ws, 'ALREADY_CONNECTED', 'Zaten aktif bir oturumunuz var.');
      }

      const sessionId = newSessionId();
      ws.role = 'viewer';
      ws.targetId = targetId;

      const timer = setTimeout(() => {
        clearPending(sessionId);
        send(ws, { type: 'connection-result', sessionId: sessionId, accepted: false, reason: 'timeout' });
      }, REQUEST_TIMEOUT_MS);
      if (timer.unref) timer.unref();

      pending.set(sessionId, { hostWs: hostWs, viewerWs: ws, timer: timer });

      send(ws, { type: 'connecting', sessionId: sessionId, targetId: targetId });
      return send(hostWs, {
        type: 'connection-request',
        from: sessionId,
        secret: secret,
        viewerMachineId: msg.viewerMachineId ? normalizeMachineId(msg.viewerMachineId) : null,
      });
    }

    // 3) HOST ONAY / RED YANITI -------------------------------------------
    case 'connection-response': {
      const sessionId = String(msg.to || '');
      const p = pending.get(sessionId);
      if (!p || p.hostWs !== ws) {
        return sendError(ws, 'NO_PENDING', 'Bekleyen bağlantı isteği bulunamadı.');
      }
      clearPending(sessionId);

      const accepted = msg.accepted === true;
      send(p.viewerWs, {
        type: 'connection-result',
        sessionId: sessionId,
        accepted: accepted,
        reason: typeof msg.reason === 'string' ? msg.reason : '',
      });

      if (accepted) {
        attachSession(sessionId, ws, p.viewerWs);
        send(ws, { type: 'session-established', sessionId: sessionId });
      } else {
        p.viewerWs.role = null;
        p.viewerWs.targetId = null;
      }
      return;
    }

    // 4) SDP / ICE / E2E ANAHTAR İLETİMİ ----------------------------------
    case 'signal': {
      const sessionId = ws.sessionId;
      if (!sessionId) return;
      const s = sessions.get(sessionId);
      if (!s) return;

      let serialized;
      try {
        serialized = JSON.stringify(msg.data || {});
      } catch (e) {
        return;
      }
      if (serialized.length > MAX_SIGNAL_BYTES) return;

      const target = s.hostWs === ws ? s.viewerWs : s.hostWs;
      return send(target, { type: 'signal', data: msg.data });
    }

    case 'leave':
      return cleanup(ws);

    default:
      return;
  }
}

function cleanup(ws) {
  // Bekleyen istekleri temizle
  pending.forEach((p, sessionId) => {
    if (p.hostWs === ws || p.viewerWs === ws) {
      clearPending(sessionId);
      send(p.hostWs === ws ? p.viewerWs : p.hostWs, {
        type: 'peer-left',
        message: 'Karşı taraf ayrıldı.',
      });
    }
  });

  // Aktif oturumu kapat
  if (ws.sessionId && sessions.has(ws.sessionId)) {
    destroySession(ws.sessionId, 'Karşı taraf bağlantıyı kapattı.');
  }

  // Host kaydını düşür (yalnızca güncel soket ise)
  if (ws.role === 'host' && ws.machineId && hosts.get(ws.machineId) === ws) {
    hosts.delete(ws.machineId);
  }

  ws.role = null;
  ws.targetId = null;
  ws.machineId = null;
  ws.sessionId = null;
}

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.role = null;
  ws.sessionId = null;
  ws.machineId = null;
  ws.clientIp = getClientIp(req);

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (raw) => {
    if (raw && raw.length > MAX_MESSAGE_BYTES) return;
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (err) {
      return;
    }
    if (msg && typeof msg.type === 'string') {
      handleMessage(ws, msg);
    }
  });

  ws.on('close', () => cleanup(ws));
  ws.on('error', () => cleanup(ws));
});

// Periyodik ping/pong heartbeat (kopan bağlantı temizliği)
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);

wss.on('close', () => clearInterval(heartbeat));

// Rate limit tablosunu periyodik temizle
const rateSweeper = setInterval(() => {
  const now = Date.now();
  rateLimits.forEach((v, k) => {
    if (now > v.resetAt) rateLimits.delete(k);
  });
}, 60000);
if (rateSweeper.unref) rateSweeper.unref();

server.listen(PORT, HOST, () => {
  console.log(`[signaling] Sunucu ${HOST}:${PORT} üzerinde çalışıyor`);
  console.log(`[signaling] Health check: http://localhost:${PORT}/health`);
});

process.on('uncaughtException', (err) => {
  console.error('[signaling] uncaughtException:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[signaling] unhandledRejection:', reason);
});
