/**
 * NexDesk — Signaling Server
 * WebRTC offer/answer relay + session lifecycle management
 * Node.js + Socket.IO
 */
'use strict';

const { createServer } = require('http');
const { Server }       = require('socket.io');
const fetch            = require('node-fetch');

const PORT            = parseInt(process.env.SIGNALING_PORT    || '7879');
const API_URL         = process.env.API_URL                    || 'http://localhost:8000';
const SIGNALING_SECRET = process.env.SIGNALING_SECRET          || 'change_me';
const REQUEST_TIMEOUT = 30_000; // 30s for host to accept

// ── In-memory state ──────────────────────────────────────
// deviceId → socketId
const deviceSockets = new Map();
// socketId → deviceId
const socketDevices = new Map();
// sessionId → { hostSocket, ctrlSocket }
const activeSessions = new Map();
// requestId → { timer, hostDeviceId, ctrlDeviceId, ctrlSocket }
const pendingRequests = new Map();

// ── HTTP server ───────────────────────────────────────────
const httpServer = createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', connections: deviceSockets.size }));
    return;
  }
  if (req.url === '/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      online_devices:   deviceSockets.size,
      active_sessions:  activeSessions.size,
      pending_requests: pendingRequests.size,
      uptime_s:         Math.round(process.uptime()),
    }));
    return;
  }
  res.writeHead(404);
  res.end();
});

const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket'],
  pingInterval: 25_000,
  pingTimeout: 10_000,
});


// ── Auth middleware ───────────────────────────────────────
io.use((socket, next) => {
  const { deviceId, token } = socket.handshake.auth;
  if (!deviceId || !token) {
    return next(new Error('Missing deviceId or token'));
  }
  // Attach to socket
  socket.deviceId = deviceId;
  socket.token    = token;
  next();
});


// ── Connection ────────────────────────────────────────────
io.on('connection', (socket) => {
  const { deviceId } = socket;

  // Disconnect previous socket for same device
  const prevSocket = deviceSockets.get(deviceId);
  if (prevSocket && prevSocket !== socket.id) {
    const prev = io.sockets.sockets.get(prevSocket);
    if (prev) prev.disconnect(true);
  }

  deviceSockets.set(deviceId, socket.id);
  socketDevices.set(socket.id, deviceId);
  console.log(`[+] ${deviceId} connected (${socket.id})`);


  // ── Request to connect to host ─────────────────────────
  socket.on('request-connection', async ({ targetId, sessionToken }) => {
    console.log(`[→] ${deviceId} requests connection to ${targetId}`);

    // Validate via API
    let apiRes;
    try {
      apiRes = await callApi('/auth/connect', 'POST', socket.token, {
        target_id: targetId, password: sessionToken || '',
      });
    } catch (err) {
      socket.emit('connection-failed', { reason: err.message });
      return;
    }

    const { authorized, requires_confirmation, method } = apiRes;
    if (!authorized) {
      socket.emit('connection-failed', { reason: 'Non autorisé' });
      return;
    }

    const hostSocket = deviceSockets.get(targetId);
    if (!hostSocket) {
      socket.emit('connection-failed', { reason: 'Hôte hors ligne' });
      return;
    }

    const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2)}`;

    // Unattended access — skip confirmation
    if (!requires_confirmation) {
      acceptConnection(requestId, targetId, deviceId, hostSocket, socket);
      return;
    }

    // Notify host — wait for acceptance
    const timer = setTimeout(() => {
      pendingRequests.delete(requestId);
      socket.emit('connection-failed', { reason: 'Timeout — hôte n\'a pas répondu' });
      console.log(`[✗] Request ${requestId} timed out`);
    }, REQUEST_TIMEOUT);

    pendingRequests.set(requestId, { timer, hostDeviceId: targetId, ctrlDeviceId: deviceId, ctrlSocket: socket });

    io.to(hostSocket).emit('incoming-connection', {
      requestId,
      controllerId: deviceId,
      method,
      timeout: REQUEST_TIMEOUT / 1000,
    });

    console.log(`[?] Pending request ${requestId}: ${deviceId} → ${targetId}`);
  });


  // ── Host accepts connection ───────────────────────────
  socket.on('accept-connection', ({ requestId }) => {
    const req = pendingRequests.get(requestId);
    if (!req || req.hostDeviceId !== deviceId) {
      socket.emit('error', { message: 'Requête introuvable' });
      return;
    }
    clearTimeout(req.timer);
    pendingRequests.delete(requestId);
    acceptConnection(requestId, deviceId, req.ctrlDeviceId, socket.id, req.ctrlSocket);
  });


  // ── Host rejects connection ───────────────────────────
  socket.on('reject-connection', ({ requestId }) => {
    const req = pendingRequests.get(requestId);
    if (!req || req.hostDeviceId !== deviceId) return;
    clearTimeout(req.timer);
    pendingRequests.delete(requestId);
    req.ctrlSocket.emit('connection-rejected', { reason: 'Refusé par l\'hôte' });
    console.log(`[✗] ${deviceId} rejected request ${requestId}`);
  });


  // ── WebRTC Signaling relay ────────────────────────────
  socket.on('webrtc-offer', ({ sessionId, sdp }) => {
    const peer = getPeerSocket(sessionId, socket.id);
    if (peer) io.to(peer).emit('webrtc-offer', { sessionId, sdp });
  });

  socket.on('webrtc-answer', ({ sessionId, sdp }) => {
    const peer = getPeerSocket(sessionId, socket.id);
    if (peer) io.to(peer).emit('webrtc-answer', { sessionId, sdp });
  });

  socket.on('webrtc-ice', ({ sessionId, candidate }) => {
    const peer = getPeerSocket(sessionId, socket.id);
    if (peer) io.to(peer).emit('webrtc-ice', { sessionId, candidate });
  });


  // ── Chat relay (fallback when DC not available) ───────
  socket.on('chat-message', ({ sessionId, text, ts }) => {
    const peer = getPeerSocket(sessionId, socket.id);
    if (peer) io.to(peer).emit('chat-message', { from: deviceId, text, ts });
  });


  // ── Session ended notification ────────────────────────
  socket.on('end-session', ({ sessionId }) => {
    const session = activeSessions.get(sessionId);
    if (!session) return;
    const peer = getPeerSocket(sessionId, socket.id);
    if (peer) io.to(peer).emit('session-ended', { by: deviceId });
    activeSessions.delete(sessionId);
    console.log(`[-] Session ${sessionId.slice(0, 8)} ended by ${deviceId}`);
  });


  // ── Disconnect ────────────────────────────────────────
  socket.on('disconnect', () => {
    deviceSockets.delete(deviceId);
    socketDevices.delete(socket.id);
    console.log(`[-] ${deviceId} disconnected`);

    // Notify peers in active sessions
    for (const [sessionId, { hostSocket, ctrlSocket }] of activeSessions) {
      if (hostSocket === socket.id || ctrlSocket === socket.id) {
        const peerSocket = hostSocket === socket.id ? ctrlSocket : hostSocket;
        io.to(peerSocket).emit('peer-disconnected', { deviceId, sessionId });
        activeSessions.delete(sessionId);
        console.log(`[-] Session ${sessionId.slice(0, 8)} cleaned up`);
      }
    }

    // Cancel pending requests
    for (const [requestId, req] of pendingRequests) {
      if (req.hostDeviceId === deviceId || req.ctrlSocket?.id === socket.id) {
        clearTimeout(req.timer);
        pendingRequests.delete(requestId);
        if (req.ctrlSocket?.id !== socket.id) {
          req.ctrlSocket.emit('connection-failed', { reason: 'Hôte déconnecté' });
        }
      }
    }
  });
});


// ── Helper: accept and set up session ────────────────────
function acceptConnection(requestId, hostDeviceId, ctrlDeviceId, hostSocketId, ctrlSocket) {
  const sessionId = `ses_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  activeSessions.set(sessionId, { hostSocket: hostSocketId, ctrlSocket: ctrlSocket.id });

  // Notify both parties
  io.to(hostSocketId).emit('connection-accepted', {
    sessionId, role: 'host', peerId: ctrlDeviceId,
  });
  ctrlSocket.emit('connection-accepted', {
    sessionId, role: 'controller', peerId: hostDeviceId,
  });

  console.log(`[✓] Session ${sessionId.slice(0, 8)}: ${ctrlDeviceId} ↔ ${hostDeviceId}`);
}


// ── Helper: get peer socket in a session ─────────────────
function getPeerSocket(sessionId, mySocketId) {
  const session = activeSessions.get(sessionId);
  if (!session) return null;
  return session.hostSocket === mySocketId ? session.ctrlSocket : session.hostSocket;
}


// ── Helper: call backend API ─────────────────────────────
async function callApi(path, method, token, body) {
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(5000),
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || `API error ${res.status}`);
  return data;
}


// ── Periodic cleanup ─────────────────────────────────────
setInterval(() => {
  // Remove sessions with disconnected peers
  for (const [id, { hostSocket, ctrlSocket }] of activeSessions) {
    const hostAlive = io.sockets.sockets.has(hostSocket);
    const ctrlAlive = io.sockets.sockets.has(ctrlSocket);
    if (!hostAlive || !ctrlAlive) {
      activeSessions.delete(id);
      console.log(`[GC] Session ${id.slice(0, 8)} cleaned up`);
    }
  }
}, 30_000);


// ── Start ─────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  console.log(`\n🚀 NexDesk Signaling Server`);
  console.log(`   Port    : ${PORT}`);
  console.log(`   API     : ${API_URL}`);
  console.log(`   Health  : http://localhost:${PORT}/health`);
  console.log(`   Stats   : http://localhost:${PORT}/stats\n`);
});
