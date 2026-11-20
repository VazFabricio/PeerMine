'use strict';

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

let pollTimer = null;
let prevPeers = 0;

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

async function refreshStatus() {
  try {
    const st = await invoke('get_status');
    if (!st.active) {
      if (prevPeers > 0) playSound('disconnect');
      prevPeers = 0;
      setBadge('Desconectado', '');
      els.statRtt.textContent = '-- ms';
      els.statRoute.textContent = '--';
      els.statPeers.textContent = '0';
      els.statTraffic.textContent = '0 KB / 0 KB';
      els.btnStop.disabled = true;
      els.btnHost.disabled = false;
      els.btnJoin.disabled = false;
      els.btnAcceptAnswer.disabled = true;
      return;
    }

    els.btnStop.disabled = false;
    els.btnHost.disabled = true;
    els.btnJoin.disabled = true;
    els.btnAcceptAnswer.disabled = st.role !== 'host';
    els.statRtt.textContent = st.rtt_ms != null ? `${st.rtt_ms} ms` : '-- ms';
    els.statRoute.textContent = st.route || '--';
    els.statPeers.textContent = String(st.peers);
    els.statTraffic.textContent = `${formatBytes(st.bytes_tx)} / ${formatBytes(st.bytes_rx)}`;

    if (st.peers > prevPeers) playSound('connect');
    prevPeers = st.peers;

    if (st.role === 'host') {
      if (st.peers > 0) setBadge(`Conectado P2P (${st.peers} jogador)`, 'ok');
      else setBadge('Host Ativo — Cole a resposta PM2: do amigo', 'warn');
    } else if (st.role === 'client') {
      if (st.peers > 0) setBadge('Conectado P2P ao Host', 'ok');
      else setBadge('Aguardando Host colar sua resposta PM2:...', 'warn');
    }

    if (st.last_error) {
      els.errorHint.textContent = st.last_error;
      els.errorHint.style.display = 'block';
    } else {
      els.errorHint.style.display = 'none';
    }
  } catch {}
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  refreshStatus();
  pollTimer = setInterval(refreshStatus, 1000);
}

els.btnHost.addEventListener('click', async () => {
  const port = parseInt(els.hostPort.value, 10);
  if (!port || port < 1 || port > 65535) {
    alert('Informe uma porta válida (1 a 65535).');
    return;
  }
  try {
    els.btnHost.disabled = true;
    setBadge('Abrindo túnel P2P...', 'warn');
    const ticket = await invoke('start_host', { mcPort: port });
    els.ticketOut.value = ticket;
    els.btnCopyTicket.disabled = false;
    els.btnAcceptAnswer.disabled = false;
    startPolling();
  } catch (err) {
    els.btnHost.disabled = false;
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
  try {
    els.btnAcceptAnswer.disabled = true;
    await invoke('accept_peer_answer', { answer });
    els.answerIn.value = '';
    setBadge('Furando NAT P2P com o amigo...', 'warn');
  } catch (err) {
    alert(String(err));
  } finally {
    els.btnAcceptAnswer.disabled = false;
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
    els.btnJoin.disabled = true;
    setBadge('Gerando resposta P2P...', 'warn');
    const answer = await invoke('start_client', { ticket, localPort: port });
    els.answerOut.value = answer;
    els.btnCopyAnswer.disabled = false;
    els.joinAddress.textContent = port === 25565 ? 'localhost (ou 127.0.0.1:25565)' : `127.0.0.1:${port}`;
    els.joinAddressBox.style.display = 'block';
    startPolling();
  } catch (err) {
    els.btnJoin.disabled = false;
    setBadge('Falha ao conectar', 'err');
    alert(String(err));
  }
});

els.btnCopyAnswer.addEventListener('click', async () => {
  await navigator.clipboard.writeText(els.answerOut.value);
  els.btnCopyAnswer.textContent = 'Copiado!';
  setTimeout(() => (els.btnCopyAnswer.textContent = 'Copiar Resposta'), 1500);
});

els.btnStop.addEventListener('click', async () => {
  await invoke('stop_tunnel');
  els.ticketOut.value = '';
  els.answerIn.value = '';
  els.answerOut.value = '';
  els.btnCopyTicket.disabled = true;
  els.btnCopyAnswer.disabled = true;
  els.btnAcceptAnswer.disabled = true;
  els.joinAddressBox.style.display = 'none';
  els.errorHint.style.display = 'none';
  await refreshStatus();
});
