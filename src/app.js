'use strict';

const MSG_OPEN = 0x01;
const MSG_DATA = 0x02;
const MSG_CLOSE = 0x03;
const MSG_ERROR = 0x04;

const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
];

const els = {
  connBadge: document.getElementById('connBadge'),
  btnStop: document.getElementById('btnStop'),
  statRtt: document.getElementById('statRtt'),
  statRoute: document.getElementById('statRoute'),
  statPeers: document.getElementById('statPeers'),
  statTraffic: document.getElementById('statTraffic'),
  errorHint: document.getElementById('errorHint'),
  hostPort: document.getElementById('hostPort'),
  btnHost: document.getElementById('btnHost'),
  btnCopyTicket: document.getElementById('btnCopyTicket'),
  ticketOut: document.getElementById('ticketOut'),
  answerIn: document.getElementById('answerIn'),
  btnAcceptAnswer: document.getElementById('btnAcceptAnswer'),
  ticketIn: document.getElementById('ticketIn'),
  clientPort: document.getElementById('clientPort'),
  btnJoin: document.getElementById('btnJoin'),
  btnCopyAnswer: document.getElementById('btnCopyAnswer'),
  answerOut: document.getElementById('answerOut'),
  joinAddressBox: document.getElementById('joinAddressBox'),
  joinAddress: document.getElementById('joinAddress'),
};

let pc = null;
let ctrlChannel = null;
let bridgeWs = null;
let statsTimer = null;
let role = 'idle'; // 'idle' | 'host' | 'client'
let wasConnected = false;
let bytesTx = 0;
let bytesRx = 0;
const dataChannels = new Map(); // connId -> { dc, queue }

function invoke(cmd, args) {
  const fn = window.__TAURI__?.core?.invoke;
  if (!fn) throw new Error('Execute dentro do app desktop PeerMine.');
  return fn(cmd, args);
}

function setBadge(text, type = '') {
  els.connBadge.textContent = text;
  els.connBadge.className = 'badge' + (type ? ' ' + type : '');
}

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(2)} MB`;
}

function playSound(kind) {
  try {
    const ctx = new AudioContext();
    const notes = kind === 'connect' ? [523.25, 659.25, 783.99] : [440, 329.63];
    const now = ctx.currentTime;
    notes.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      const t0 = now + idx * 0.08;
      gain.gain.setValueAtTime(0.0001, t0);
      gain.gain.exponentialRampToValueAtTime(0.07, t0 + 0.015);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.15);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(t0);
      osc.stop(t0 + 0.16);
    });
    setTimeout(() => ctx.close().catch(() => {}), 500);
  } catch {}
}

function toBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str) {
  const clean = str.replace(/[^A-Za-z0-9\-_]/g, '');
  const pad = (4 - (clean.length % 4)) % 4;
  const b64 = clean.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Mantém apenas candidatos UDP P2P (remove TCP) para reduzir o tamanho do código e forçar UDP direto
function compactSdp(sdp) {
  const lines = sdp.split(/\r?\n/);
  const out = [];
  for (const line of lines) {
    if (!line) continue;
    if (line.startsWith('a=candidate:') && /\s+tcp\s+/i.test(line)) continue;
    out.push(line);
  }
  return out.join('\r\n') + '\r\n';
}

async function encodeSignal(prefix, desc) {
  const sdp = compactSdp(desc.sdp);
  const compact = JSON.stringify({ t: desc.type === 'offer' ? 'o' : 'a', s: sdp });
  const rawBytes = new TextEncoder().encode(compact);
  if (typeof CompressionStream !== 'undefined') {
    const cs = new CompressionStream('deflate-raw');
    const writer = cs.writable.getWriter();
    writer.write(rawBytes);
    writer.close();
    const compressed = new Uint8Array(await new Response(cs.readable).arrayBuffer());
    return prefix + toBase64Url(compressed);
  }
  return prefix + '0_' + toBase64Url(rawBytes);
}

async function decodeSignal(expectedPrefix, input) {
  const clean = input.replace(/\s+/g, '');
  if (!clean.startsWith(expectedPrefix)) {
    throw new Error(`Código inválido. Deve começar com ${expectedPrefix}`);
  }
  let body = clean.slice(expectedPrefix.length);
  let jsonStr;
  if (body.startsWith('0_')) {
    jsonStr = new TextDecoder().decode(fromBase64Url(body.slice(2)));
  } else {
    const compressed = fromBase64Url(body);
    const ds = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    writer.write(compressed);
    writer.close();
    jsonStr = await new Response(ds.readable).text();
  }
  const obj = JSON.parse(jsonStr);
  return { type: obj.t === 'o' ? 'offer' : 'answer', sdp: obj.s };
}

function waitIceGathering(peerConn, timeoutMs = 1500) {
  if (peerConn.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      peerConn.removeEventListener('icegatheringstatechange', onChange);
      resolve();
    }, timeoutMs);
    function onChange() {
      if (peerConn.iceGatheringState === 'complete') {
        clearTimeout(timer);
        peerConn.removeEventListener('icegatheringstatechange', onChange);
        resolve();
      }
    }
    peerConn.addEventListener('icegatheringstatechange', onChange);
  });
}

function makeBridgeFrame(msgType, connId, payloadBytes) {
  const plen = payloadBytes ? payloadBytes.byteLength : 0;
  const buf = new Uint8Array(5 + plen);
  buf[0] = msgType;
  buf[1] = (connId >>> 24) & 0xff;
  buf[2] = (connId >>> 16) & 0xff;
  buf[3] = (connId >>> 8) & 0xff;
  buf[4] = connId & 0xff;
  if (plen > 0) buf.set(payloadBytes, 5);
  return buf;
}

function sendToBridge(msgType, connId, payloadBytes) {
  if (bridgeWs && bridgeWs.readyState === WebSocket.OPEN) {
    bridgeWs.send(makeBridgeFrame(msgType, connId, payloadBytes));
  }
}

async function ensureBridgeWs() {
  if (bridgeWs && bridgeWs.readyState === WebSocket.OPEN) return;
  const info = await invoke('get_bridge_info');
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${info.port}/?token=${encodeURIComponent(info.token)}`);
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => {
      bridgeWs = ws;
      resolve();
    };
    ws.onerror = () => reject(new Error('Falha ao conectar ao bridge TCP local.'));
    ws.onmessage = (ev) => handleBridgeMessage(new Uint8Array(ev.data));
    ws.onclose = () => {
      if (bridgeWs === ws) bridgeWs = null;
    };
  });
}

function attachDataChannelHandlers(connId, entry) {
  const dc = entry.dc;
  dc.binaryType = 'arraybuffer';

  dc.onopen = () => {
    while (entry.queue.length > 0 && dc.readyState === 'open') {
      const chunk = entry.queue.shift();
      dc.send(chunk);
      bytesTx += chunk.byteLength;
    }
  };

  dc.onmessage = (ev) => {
    const data = new Uint8Array(ev.data);
    bytesRx += data.byteLength;
    sendToBridge(MSG_DATA, connId, data);
  };

  dc.onclose = () => {
    dataChannels.delete(connId);
    sendToBridge(MSG_CLOSE, connId, null);
  };

  dc.onerror = () => {
    dataChannels.delete(connId);
    sendToBridge(MSG_CLOSE, connId, null);
  };
}

function handleBridgeMessage(frame) {
  if (frame.byteLength < 5) return;
  const msgType = frame[0];
  const connId =
    ((frame[1] << 24) | (frame[2] << 16) | (frame[3] << 8) | frame[4]) >>> 0;
  const payload = frame.subarray(5);

  if (msgType === MSG_OPEN && role === 'client') {
    if (!pc || pc.connectionState !== 'connected') {
      sendToBridge(MSG_CLOSE, connId, null);
      return;
    }
    const dc = pc.createDataChannel(`mc:${connId}`, { ordered: true });
    const entry = { dc, queue: [] };
    dataChannels.set(connId, entry);
    attachDataChannelHandlers(connId, entry);
    return;
  }

  if (msgType === MSG_DATA) {
    const entry = dataChannels.get(connId);
    if (!entry) return;
    const copy = new Uint8Array(payload);
    if (entry.dc.readyState === 'open') {
      entry.dc.send(copy);
      bytesTx += copy.byteLength;
    } else if (entry.dc.readyState === 'connecting') {
      entry.queue.push(copy);
    }
    return;
  }

  if (msgType === MSG_CLOSE) {
    const entry = dataChannels.get(connId);
    if (entry) {
      dataChannels.delete(connId);
      try {
        entry.dc.close();
      } catch {}
    }
    return;
  }

  if (msgType === MSG_ERROR) {
    const msg = new TextDecoder().decode(payload);
    els.errorHint.textContent = msg;
    els.errorHint.style.display = 'block';
  }
}

function createPeerConnection() {
  const conn = new RTCPeerConnection({ iceServers: ICE_SERVERS });

  conn.ondatachannel = (ev) => {
    const dc = ev.channel;
    if (dc.label === 'ctrl') return;
    if (dc.label.startsWith('mc:')) {
      const connId = parseInt(dc.label.slice(3), 10);
      if (!connId) return;
      const entry = { dc, queue: [] };
      dataChannels.set(connId, entry);
      attachDataChannelHandlers(connId, entry);
      sendToBridge(MSG_OPEN, connId, null);
    }
  };

  conn.onconnectionstatechange = async () => {
    const state = conn.connectionState;
    if (state === 'connected') {
      if (!wasConnected) {
        wasConnected = true;
        playSound('connect');
      }
      els.statPeers.textContent = '1';
      setBadge(
        role === 'host' ? 'Conectado P2P (1 jogador)' : 'Conectado P2P ao Host',
        'ok'
      );
      if (role === 'client') {
        const port = parseInt(els.clientPort.value, 10) || 25565;
        try {
          await invoke('start_client_tcp', { localPort: port });
        } catch (e) {
          els.errorHint.textContent = String(e);
          els.errorHint.style.display = 'block';
        }
      }
    } else if (state === 'connecting') {
      setBadge('Furando NAT P2P (ICE/STUN)...', 'warn');
    } else if (state === 'disconnected' || state === 'failed' || state === 'closed') {
      if (wasConnected) {
        wasConnected = false;
        playSound('disconnect');
      }
      els.statPeers.textContent = '0';
      if (role !== 'idle') {
        setBadge(state === 'failed' ? 'Falha na conexão P2P' : 'Conexão P2P encerrada', 'err');
      }
    }
  };

  return conn;
}

function startStatsPolling() {
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(async () => {
    els.statTraffic.textContent = `${formatBytes(bytesTx)} / ${formatBytes(bytesRx)}`;
    if (!pc || pc.connectionState !== 'connected') return;
    try {
      const report = await pc.getStats();
      let selectedPair = null;
      const candidates = new Map();
      report.forEach((stat) => {
        if (stat.type === 'remote-candidate' || stat.type === 'local-candidate') {
          candidates.set(stat.id, stat);
        }
        if (stat.type === 'candidate-pair' && stat.nominated && stat.state === 'succeeded') {
          selectedPair = stat;
        }
      });
      if (selectedPair) {
        if (typeof selectedPair.currentRoundTripTime === 'number') {
          els.statRtt.textContent = `${Math.round(selectedPair.currentRoundTripTime * 1000)} ms`;
        }
        const rem = candidates.get(selectedPair.remoteCandidateId);
        const isV6 = rem?.address?.includes(':');
        els.statRoute.textContent = isV6
          ? 'Direto P2P (WebRTC UDP IPv6)'
          : 'Direto P2P (WebRTC UDP IPv4)';
      }
    } catch {}
  }, 1000);
}

async function resetAll() {
  if (statsTimer) {
    clearInterval(statsTimer);
    statsTimer = null;
  }
  for (const entry of dataChannels.values()) {
    try {
      entry.dc.close();
    } catch {}
  }
  dataChannels.clear();
  if (ctrlChannel) {
    try {
      ctrlChannel.close();
    } catch {}
    ctrlChannel = null;
  }
  if (pc) {
    try {
      pc.close();
    } catch {}
    pc = null;
  }
  await invoke('stop_tunnel').catch(() => {});
  role = 'idle';
  wasConnected = false;
  bytesTx = 0;
  bytesRx = 0;
  setBadge('Desconectado', '');
  els.statRtt.textContent = '-- ms';
  els.statRoute.textContent = '--';
  els.statPeers.textContent = '0';
  els.statTraffic.textContent = '0 KB / 0 KB';
  els.btnStop.disabled = true;
  els.btnHost.disabled = false;
  els.btnJoin.disabled = false;
  els.btnAcceptAnswer.disabled = true;
  els.btnCopyTicket.disabled = true;
  els.btnCopyAnswer.disabled = true;
  els.ticketOut.value = '';
  els.answerIn.value = '';
  els.answerOut.value = '';
  els.joinAddressBox.style.display = 'none';
  els.errorHint.style.display = 'none';
}

els.btnHost.addEventListener('click', async () => {
  const port = parseInt(els.hostPort.value, 10);
  if (!port || port < 1 || port > 65535) {
    alert('Informe uma porta válida (1 a 65535).');
    return;
  }
  try {
    await resetAll();
    role = 'host';
    els.btnHost.disabled = true;
    els.btnJoin.disabled = true;
    els.btnStop.disabled = false;
    setBadge('Coletando ICE/STUN P2P...', 'warn');

    await ensureBridgeWs();
    await invoke('start_host_tcp', { mcPort: port });

    pc = createPeerConnection();
    ctrlChannel = pc.createDataChannel('ctrl', { ordered: true });
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await waitIceGathering(pc, 1500);

    const code = await encodeSignal('PM1:', pc.localDescription);
    els.ticketOut.value = code;
    els.btnCopyTicket.disabled = false;
    els.btnAcceptAnswer.disabled = false;
    els.statRoute.textContent = 'Aguardando PM2: (WebRTC STUN)';
    setBadge('Host Ativo — Cole a resposta PM2: do amigo', 'warn');
    startStatsPolling();
  } catch (err) {
    await resetAll();
    setBadge('Erro ao hostear', 'err');
    alert(String(err));
  }
});

els.btnAcceptAnswer.addEventListener('click', async () => {
  const answer = els.answerIn.value.trim();
  if (!answer) {
    alert('Cole a resposta PM2:... enviada pelo amigo.');
    return;
  }
  if (!pc) return;
  try {
    els.btnAcceptAnswer.disabled = true;
    const desc = await decodeSignal('PM2:', answer);
    await pc.setRemoteDescription(desc);
    els.answerIn.value = '';
    setBadge('Furando NAT P2P (ICE/STUN)...', 'warn');
  } catch (err) {
    els.btnAcceptAnswer.disabled = false;
    alert(String(err));
  }
});

els.btnCopyTicket.addEventListener('click', async () => {
  await navigator.clipboard.writeText(els.ticketOut.value);
  els.btnCopyTicket.textContent = 'Copiado!';
  setTimeout(() => (els.btnCopyTicket.textContent = 'Copiar Código'), 1500);
});

els.btnJoin.addEventListener('click', async () => {
  const ticket = els.ticketIn.value.trim();
  const port = parseInt(els.clientPort.value, 10);
  if (!ticket) {
    alert('Cole o código PM1:... do Host.');
    return;
  }
  if (!port || port < 1 || port > 65535) {
    alert('Informe uma porta local válida (1 a 65535).');
    return;
  }
  try {
    await resetAll();
    role = 'client';
    els.btnHost.disabled = true;
    els.btnJoin.disabled = true;
    els.btnStop.disabled = false;
    setBadge('Gerando resposta ICE/STUN...', 'warn');

    await ensureBridgeWs();
    const offerDesc = await decodeSignal('PM1:', ticket);

    pc = createPeerConnection();
    await pc.setRemoteDescription(offerDesc);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await waitIceGathering(pc, 1500);

    const answerCode = await encodeSignal('PM2:', pc.localDescription);
    els.answerOut.value = answerCode;
    els.btnCopyAnswer.disabled = false;
    els.joinAddress.textContent =
      port === 25565 ? 'localhost (ou 127.0.0.1:25565)' : `127.0.0.1:${port}`;
    els.joinAddressBox.style.display = 'block';
    els.statRoute.textContent = 'Aguardando Host colar PM2:';
    setBadge('Aguardando Host colar sua resposta PM2:...', 'warn');
    startStatsPolling();
  } catch (err) {
    await resetAll();
    setBadge('Falha ao conectar', 'err');
    alert(String(err));
  }
});

els.btnCopyAnswer.addEventListener('click', async () => {
  await navigator.clipboard.writeText(els.answerOut.value);
  els.btnCopyAnswer.textContent = 'Copiado!';
  setTimeout(() => (els.btnCopyAnswer.textContent = 'Copiar Resposta'), 1500);
});

els.btnStop.addEventListener('click', resetAll);
