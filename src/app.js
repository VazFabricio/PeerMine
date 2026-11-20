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
  ticketIn: document.getElementById('ticketIn'),
  clientPort: document.getElementById('clientPort'),
  btnJoin: document.getElementById('btnJoin'),
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
      return;
    }

    els.btnStop.disabled = false;
    els.btnHost.disabled = true;
    els.btnJoin.disabled = true;
    els.statRtt.textContent = st.rtt_ms != null ? `${st.rtt_ms} ms` : '-- ms';
    els.statRoute.textContent = st.route || '--';
    els.statPeers.textContent = String(st.peers);
    els.statTraffic.textContent = `${formatBytes(st.bytes_tx)} / ${formatBytes(st.bytes_rx)}`;

    if (st.peers > prevPeers) playSound('connect');
    prevPeers = st.peers;

    if (st.role === 'host') {
      if (st.peers > 0) setBadge(`Conectado P2P (${st.peers} jogador)`, 'ok');
      else setBadge('Host Ativo — Aguardando amigos...', 'warn');
    } else if (st.role === 'client') {
      if (st.peers > 0) setBadge('Conectado P2P ao Host', 'ok');
      else setBadge('Conexão encerrada', 'err');
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
    startPolling();
  } catch (err) {
    els.btnHost.disabled = false;
    setBadge('Erro ao hostear', 'err');
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
    els.btnJoin.disabled = true;
    setBadge('Conectando ao Host P2P...', 'warn');
    await invoke('start_client', { ticket, localPort: port });
    els.joinAddress.textContent = port === 25565 ? 'localhost (ou 127.0.0.1:25565)' : `127.0.0.1:${port}`;
    els.joinAddressBox.style.display = 'block';
    playSound('connect');
    startPolling();
  } catch (err) {
    els.btnJoin.disabled = false;
    setBadge('Falha ao conectar', 'err');
    alert(String(err));
  }
});

els.btnStop.addEventListener('click', async () => {
  await invoke('stop_tunnel');
  els.ticketOut.value = '';
  els.btnCopyTicket.disabled = true;
  els.joinAddressBox.style.display = 'none';
  els.errorHint.style.display = 'none';
  await refreshStatus();
});
