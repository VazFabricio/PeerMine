use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use iroh::endpoint::{
    AckFrequencyConfig, BindOpts, IdleTimeout, MtuDiscoveryConfig, QuicTransportConfig, VarInt,
};
use iroh::{Endpoint, EndpointAddr, TransportAddr, Watcher};
use noq_proto::congestion::Bbr3Config;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};

const ALPN: &[u8] = b"peermine/1";

const STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
];

#[derive(Clone, Serialize)]
pub struct TunnelStatus {
    pub active: bool,
    pub role: String, // "idle" | "host" | "client"
    pub ticket: String,
    pub route: String,
    pub rtt_ms: Option<u64>,
    pub peers: usize,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub last_error: Option<String>,
}

struct ActiveSession {
    stop: Arc<AtomicBool>,
    role: String,
    ticket: String,
    peers: Arc<AtomicUsize>,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
    route: Arc<Mutex<String>>,
    rtt_ms: Arc<Mutex<Option<u64>>>,
    last_error: Arc<Mutex<Option<String>>>,
}

pub struct TunnelState {
    runtime: tokio::runtime::Runtime,
    session: Mutex<Option<ActiveSession>>,
}

impl Default for TunnelState {
    fn default() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("falha ao iniciar runtime tokio");
        Self {
            runtime,
            session: Mutex::new(None),
        }
    }
}

fn encode_ticket(addr: &EndpointAddr) -> Result<String, String> {
    let json = serde_json::to_vec(addr).map_err(|e| format!("Erro ao serializar ticket: {e}"))?;
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&json)
        .map_err(|e| format!("Erro ao comprimir ticket: {e}"))?;
    let compressed = enc
        .finish()
        .map_err(|e| format!("Erro ao finalizar compressão: {e}"))?;
    Ok(format!("PM1:{}", URL_SAFE_NO_PAD.encode(compressed)))
}

fn decode_ticket(input: &str) -> Result<EndpointAddr, String> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let payload = clean
        .strip_prefix("PM1:")
        .ok_or_else(|| "Código inválido. Deve começar com PM1:".to_string())?;
    let compressed = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("Base64 inválido: {e}"))?;
    let mut dec = DeflateDecoder::new(&compressed[..]);
    let mut json = Vec::new();
    dec.read_to_end(&mut json)
        .map_err(|e| format!("Ticket corrompido: {e}"))?;
    serde_json::from_slice(&json).map_err(|e| format!("JSON do ticket inválido: {e}"))
}

/// Constrói um pacote RFC 5389 STUN Binding Request (20 bytes).
fn build_stun_binding_request(tx_id: &[u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    // Binding Request (0x0001), Length = 0 (0x0000)
    req[0] = 0x00;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x00;
    // Magic Cookie (0x2112A442)
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xA4;
    req[7] = 0x42;
    req[8..20].copy_from_slice(tx_id);
    req
}

/// Decodifica a resposta STUN RFC 5389 extraindo XOR-MAPPED-ADDRESS (0x0020) ou MAPPED-ADDRESS (0x0001).
fn parse_stun_binding_response(buf: &[u8], expected_tx_id: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    // Binding Success Response = 0x0101
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return None;
    }
    // Magic Cookie = 0x2112A442
    if buf[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        return None;
    }
    if &buf[8..20] != expected_tx_id {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());
    let mut pos = 20;
    let mut fallback_mapped: Option<SocketAddr> = None;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > end {
            break;
        }
        let val = &buf[pos..pos + attr_len];

        // XOR-MAPPED-ADDRESS (0x0020)
        if attr_type == 0x0020 && val.len() >= 8 && val[1] == 0x01 {
            let xport = u16::from_be_bytes([val[2], val[3]]) ^ 0x2112;
            let ip = Ipv4Addr::new(val[4] ^ 0x21, val[5] ^ 0x12, val[6] ^ 0xA4, val[7] ^ 0x42);
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, xport)));
        }
        // MAPPED-ADDRESS (0x0001)
        if attr_type == 0x0001 && val.len() >= 8 && val[1] == 0x01 {
            let port = u16::from_be_bytes([val[2], val[3]]);
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            fallback_mapped = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }

        // Atributos STUN são alinhados em múltiplos de 4 bytes
        let padded = (attr_len + 3) & !3;
        pos += padded;
    }

    fallback_mapped
}

/// Descobre o endereço IPv4 público:porta via STUN (Google/Cloudflare, como no projeto conversa)
/// usando a mesma porta UDP local que será entregue ao Endpoint QUIC, e opcionalmente
/// envia pacotes UDP de pre-punching para abrir o NAT local em direção ao par remoto.
async fn discover_stun_and_prepare_port(
    pre_punch_targets: &[SocketAddr],
) -> (u16, Option<SocketAddr>) {
    let Ok(sock) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await else {
        return (0, None);
    };
    let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);

    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut tx_id = [0u8; 12];
    for (i, b) in tx_id.iter_mut().enumerate() {
        *b = ((now_nanos >> (i * 5)) as u8) ^ ((local_port as u8).wrapping_mul((i as u8) + 3));
    }
    let req = build_stun_binding_request(&tx_id);

    for server in STUN_SERVERS {
        if let Ok(Ok(addrs)) =
            tokio::time::timeout(Duration::from_millis(250), lookup_host(*server)).await
        {
            for addr in addrs.filter(|a| a.is_ipv4()) {
                let _ = sock.send_to(&req, addr).await;
            }
        }
    }

    let mut discovered = None;
    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(550);

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _src))) => {
                if let Some(mapped) = parse_stun_binding_response(&buf[..n], &tx_id) {
                    discovered = Some(mapped);
                    break;
                }
            }
            _ => break,
        }
    }

    // Pre-punching UDP: abre a tabela de estado do NAT local em direção aos candidatos IPv4 do Host
    for target in pre_punch_targets {
        if target.is_ipv4() {
            let _ = sock.send_to(b"\x00", *target).await;
        }
    }

    drop(sock);
    (local_port, discovered)
}

/// Constrói um Endpoint P2P puro (Zero Relay) pré-configurado com STUN + UPnP/NAT-PMP + IPv6 + BBRv3.
async fn bind_pure_p2p_endpoint(
    with_alpn: bool,
    pre_punch_targets: &[SocketAddr],
) -> Result<(Endpoint, Option<SocketAddr>), String> {
    let (local_v4_port, stun_addr) = discover_stun_and_prepare_port(pre_punch_targets).await;

    let configure_builder = |use_fixed_port: bool| {
        let mut builder = Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
            .transport_config(low_latency_transport());

        if with_alpn {
            builder = builder.alpns(vec![ALPN.to_vec()]);
        }

        if use_fixed_port && local_v4_port != 0 {
            builder = builder.clear_ip_transports();
            if let Ok(b) = builder.bind_addr(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                local_v4_port,
            ))) {
                builder = b;
                if let Ok(b6) = builder.bind_addr_with_opts(
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                    BindOpts::default().set_is_required(false),
                ) {
                    builder = b6;
                } else {
                    builder = Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
                        .transport_config(low_latency_transport());
                    if with_alpn {
                        builder = builder.alpns(vec![ALPN.to_vec()]);
                    }
                }
            } else {
                builder = Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
                    .transport_config(low_latency_transport());
                if with_alpn {
                    builder = builder.alpns(vec![ALPN.to_vec()]);
                }
            }
        }

        if let Some(ext) = stun_addr {
            builder = builder.external_addr(ext);
            if local_v4_port != 0 && ext.port() != local_v4_port {
                builder = builder.external_addr(SocketAddr::new(ext.ip(), local_v4_port));
            }
        }

        builder
    };

    let endpoint = match configure_builder(true).bind().await {
        Ok(ep) => ep,
        Err(_) => configure_builder(false)
            .bind()
            .await
            .map_err(|e| format!("Erro ao criar endpoint P2P: {e}"))?,
    };

    Ok((endpoint, stun_addr))
}

/// Transporte QUIC ajustado para jogos em tempo real (Minecraft):
/// - Controle de congestionamento Google BBRv3 (evita bufferbloat ao carregar chunks)
/// - ACK imediato (1ms max_ack_delay e threshold 0) para combate contra mobs e drops de itens
/// - MTU limitado a 1380 bytes para evitar fragmentação e blackholes em redes PPPoE/IPv6 no Brasil
/// - Janelas calibradas para impedir filas longas de chunks na frente de pacotes de combate
fn low_latency_transport() -> QuicTransportConfig {
    let mut ack_cfg = AckFrequencyConfig::default();
    ack_cfg
        .ack_eliciting_threshold(VarInt::from_u32(0))
        .max_ack_delay(Some(Duration::from_millis(1)))
        .reordering_threshold(VarInt::from_u32(1));

    let mut mtu_cfg = MtuDiscoveryConfig::default();
    mtu_cfg
        .upper_bound(1380)
        .black_hole_cooldown(Duration::from_secs(15));

    let mut builder = QuicTransportConfig::builder()
        .congestion_controller_factory(Arc::new(Bbr3Config::default()))
        .keep_alive_interval(Duration::from_secs(2))
        .initial_rtt(Duration::from_millis(35))
        .ack_frequency_config(Some(ack_cfg))
        .min_mtu(1200)
        .initial_mtu(1280)
        .mtu_discovery_config(Some(mtu_cfg))
        .stream_receive_window(VarInt::from_u32(384 * 1024))
        .receive_window(VarInt::from_u32(768 * 1024))
        .send_window(384 * 1024)
        .enable_segmentation_offload(false)
        .send_observed_address_reports(true)
        .receive_observed_address_reports(true);

    if let Ok(idle) = IdleTimeout::try_from(Duration::from_secs(30)) {
        builder = builder.max_idle_timeout(Some(idle));
    }

    builder.build()
}

fn format_selected_route(remote_addr: &TransportAddr) -> String {
    match remote_addr {
        TransportAddr::Ip(sock) if sock.is_ipv6() => "Direto P2P (UDP IPv6 • BBRv3)".to_string(),
        TransportAddr::Ip(_) => "Direto P2P (UDP IPv4 • BBRv3)".to_string(),
        _ => "Direto P2P (UDP • BBRv3)".to_string(),
    }
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private() && !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_unicast_link_local()
                && !v6.is_unique_local()
        }
    }
}

async fn relay_bidirectional(
    tcp: TcpStream,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
) {
    let _ = tcp.set_nodelay(true);
    let _ = send.set_priority(10);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // Fatias de 16 KB (em vez de 64 KB) reduzem jitter e evitam que rajadas de chunks
    // monopolizem o escalonador antes de pacotes pequenos de combate/quebra de bloco.
    let t1 = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
    };

    let t2 = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) | Err(_) => break,
                Ok(Some(n)) => {
                    if tcp_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        let _ = tcp_w.shutdown().await;
    };

    tokio::join!(t1, t2);
}

impl TunnelState {
    pub fn stop(&self) {
        if let Ok(mut guard) = self.session.lock() {
            if let Some(sess) = guard.take() {
                sess.stop.store(true, Ordering::Relaxed);
            }
        }
    }

    pub fn status(&self) -> TunnelStatus {
        let Ok(guard) = self.session.lock() else {
            return TunnelStatus {
                active: false,
                role: "idle".into(),
                ticket: String::new(),
                route: "--".into(),
                rtt_ms: None,
                peers: 0,
                bytes_tx: 0,
                bytes_rx: 0,
                last_error: None,
            };
        };
        if let Some(s) = guard.as_ref() {
            TunnelStatus {
                active: !s.stop.load(Ordering::Relaxed),
                role: s.role.clone(),
                ticket: s.ticket.clone(),
                route: s.route.lock().map(|g| g.clone()).unwrap_or_default(),
                rtt_ms: s.rtt_ms.lock().ok().and_then(|g| *g),
                peers: s.peers.load(Ordering::Relaxed),
                bytes_tx: s.bytes_tx.load(Ordering::Relaxed),
                bytes_rx: s.bytes_rx.load(Ordering::Relaxed),
                last_error: s.last_error.lock().ok().and_then(|g| g.clone()),
            }
        } else {
            TunnelStatus {
                active: false,
                role: "idle".into(),
                ticket: String::new(),
                route: "--".into(),
                rtt_ms: None,
                peers: 0,
                bytes_tx: 0,
                bytes_rx: 0,
                last_error: None,
            }
        }
    }

    pub fn start_host(&self, mc_port: u16) -> Result<String, String> {
        self.stop();

        let (endpoint, stun_addr, addr) = self.runtime.block_on(async {
            let (endpoint, stun_addr) = bind_pure_p2p_endpoint(true, &[]).await?;

            // Aguarda até 750ms para o portmapper (UPnP/NAT-PMP/PCP) e coletor IPv6
            // adicionarem todas as rotas diretas disponíveis antes de gerar o ticket PM1:
            let mut watcher = endpoint.watch_addr();
            let deadline = tokio::time::Instant::now() + Duration::from_millis(750);
            loop {
                let current = watcher.get();
                let has_public = current.addrs.iter().any(|a| match a {
                    TransportAddr::Ip(s) => is_public_ip(&s.ip()),
                    _ => false,
                });
                if has_public && current.addrs.len() >= 2 {
                    break;
                }
                if tokio::time::timeout_at(deadline, watcher.updated())
                    .await
                    .is_err()
                {
                    break;
                }
            }

            let addr = endpoint.addr();
            Ok::<_, String>((endpoint, stun_addr, addr))
        })?;

        let has_ipv6 = addr
            .addrs
            .iter()
            .any(|a| matches!(a, TransportAddr::Ip(s) if s.is_ipv6() && is_public_ip(&s.ip())));
        let initial_route = match (stun_addr.is_some(), has_ipv6) {
            (true, true) => "Aguardando (P2P Direto: STUN IPv4 + IPv6)".to_string(),
            (true, false) => "Aguardando (P2P Direto: STUN/UPnP IPv4)".to_string(),
            (false, true) => "Aguardando (P2P Direto: IPv6)".to_string(),
            (false, false) => "Aguardando (P2P Direto: LAN/UPnP)".to_string(),
        };

        let ticket = encode_ticket(&addr)?;
        let stop = Arc::new(AtomicBool::new(false));
        let peers = Arc::new(AtomicUsize::new(0));
        let bytes_tx = Arc::new(AtomicU64::new(0));
        let bytes_rx = Arc::new(AtomicU64::new(0));
        let route = Arc::new(Mutex::new(initial_route));
        let rtt_ms = Arc::new(Mutex::new(None));
        let last_error = Arc::new(Mutex::new(None));

        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(ActiveSession {
                stop: Arc::clone(&stop),
                role: "host".into(),
                ticket: ticket.clone(),
                peers: Arc::clone(&peers),
                bytes_tx: Arc::clone(&bytes_tx),
                bytes_rx: Arc::clone(&bytes_rx),
                route: Arc::clone(&route),
                rtt_ms: Arc::clone(&rtt_ms),
                last_error: Arc::clone(&last_error),
            });
        }

        self.runtime.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let incoming = tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {
                        if stop.load(Ordering::Relaxed) { break; }
                        continue;
                    }
                    inc = endpoint.accept() => inc,
                };

                let Some(inc) = incoming else { break };
                let stop_c = Arc::clone(&stop);
                let peers_c = Arc::clone(&peers);
                let tx_c = Arc::clone(&bytes_tx);
                let rx_c = Arc::clone(&bytes_rx);
                let route_c = Arc::clone(&route);
                let rtt_c = Arc::clone(&rtt_ms);
                let err_c = Arc::clone(&last_error);

                tokio::spawn(async move {
                    let conn = match inc.await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    peers_c.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut g) = route_c.lock() {
                        *g = "Direto P2P (UDP • BBRv3)".to_string();
                    }

                    // Monitora RTT e rota direta P2P do colega
                    let conn_mon = conn.clone();
                    let stop_mon = Arc::clone(&stop_c);
                    let route_mon = Arc::clone(&route_c);
                    let rtt_mon = Arc::clone(&rtt_c);
                    tokio::spawn(async move {
                        while !stop_mon.load(Ordering::Relaxed) && conn_mon.close_reason().is_none() {
                            let paths = conn_mon.paths();
                            if let Some(sel) = paths.iter().find(|x| x.is_selected()) {
                                if let Ok(mut g) = rtt_mon.lock() {
                                    *g = Some(sel.rtt().as_millis() as u64);
                                }
                                if let Ok(mut rg) = route_mon.lock() {
                                    *rg = format_selected_route(sel.remote_addr());
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    });

                    while !stop_c.load(Ordering::Relaxed) {
                        let stream = tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                                if stop_c.load(Ordering::Relaxed) || conn.close_reason().is_some() { break; }
                                continue;
                            }
                            st = conn.accept_bi() => st,
                        };
                        let Ok((send, recv)) = stream else { break };
                        let tx_s = Arc::clone(&tx_c);
                        let rx_s = Arc::clone(&rx_c);
                        let err_s = Arc::clone(&err_c);
                        tokio::spawn(async move {
                            match TcpStream::connect(("127.0.0.1", mc_port)).await {
                                Ok(tcp) => relay_bidirectional(tcp, send, recv, tx_s, rx_s).await,
                                Err(e) => {
                                    if let Ok(mut g) = err_s.lock() {
                                        *g = Some(format!(
                                            "Minecraft não encontrado na porta {mc_port} ({e})"
                                        ));
                                    }
                                }
                            }
                        });
                    }

                    conn.close(0u32.into(), b"bye");
                    peers_c.fetch_sub(1, Ordering::Relaxed);
                });
            }
            endpoint.close().await;
        });

        Ok(ticket)
    }

    pub fn start_client(&self, ticket: &str, local_port: u16) -> Result<(), String> {
        self.stop();
        let remote_addr = decode_ticket(ticket)?;

        // Garante P2P puro removendo qualquer endereço de relay caso venha de um código antigo
        let mut clean_remote = remote_addr;
        clean_remote.addrs.retain(|a| a.is_ip());
        let pre_punch_targets: Vec<SocketAddr> = clean_remote
            .addrs
            .iter()
            .filter_map(|a| match a {
                TransportAddr::Ip(s) => Some(*s),
                _ => None,
            })
            .collect();

        let (endpoint, conn, listener) = self.runtime.block_on(async {
            let listener = TcpListener::bind(("127.0.0.1", local_port))
                .await
                .map_err(|e| format!("Porta local {local_port} ocupada ou bloqueada: {e}"))?;

            let (endpoint, _) = bind_pure_p2p_endpoint(false, &pre_punch_targets).await?;

            let conn = tokio::time::timeout(
                Duration::from_secs(12),
                endpoint.connect(clean_remote.clone(), ALPN),
            )
            .await
            .map_err(|_| {
                "Timeout ao conectar P2P direto ao Host (sem relay; verifique IPv6/UPnP/firewall)"
                    .to_string()
            })?
            .map_err(|e| format!("Falha ao conectar P2P direto ao Host: {e}"))?;

            Ok::<_, String>((endpoint, conn, listener))
        })?;

        let stop = Arc::new(AtomicBool::new(false));
        let peers = Arc::new(AtomicUsize::new(1));
        let bytes_tx = Arc::new(AtomicU64::new(0));
        let bytes_rx = Arc::new(AtomicU64::new(0));
        let route = Arc::new(Mutex::new("Direto P2P (UDP • BBRv3)".to_string()));
        let rtt_ms = Arc::new(Mutex::new(None));
        let last_error = Arc::new(Mutex::new(None));

        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(ActiveSession {
                stop: Arc::clone(&stop),
                role: "client".into(),
                ticket: String::new(),
                peers: Arc::clone(&peers),
                bytes_tx: Arc::clone(&bytes_tx),
                bytes_rx: Arc::clone(&bytes_rx),
                route: Arc::clone(&route),
                rtt_ms: Arc::clone(&rtt_ms),
                last_error: Arc::clone(&last_error),
            });
        }

        let shared_conn = Arc::new(tokio::sync::Mutex::new(conn));

        // Monitora RTT, rota direta (IPv4/IPv6) e reconecta automaticamente se a sessão QUIC cair
        let conn_mon = Arc::clone(&shared_conn);
        let ep_mon = endpoint.clone();
        let remote_mon = clean_remote.clone();
        let stop_mon = Arc::clone(&stop);
        let peers_mon = Arc::clone(&peers);
        let route_mon = Arc::clone(&route);
        let rtt_mon = Arc::clone(&rtt_ms);
        let err_mon = Arc::clone(&last_error);

        self.runtime.spawn(async move {
            while !stop_mon.load(Ordering::Relaxed) {
                let active_conn = { conn_mon.lock().await.clone() };
                if active_conn.close_reason().is_none() {
                    peers_mon.store(1, Ordering::Relaxed);
                    let paths = active_conn.paths();
                    if let Some(sel) = paths.iter().find(|x| x.is_selected()) {
                        if let Ok(mut g) = rtt_mon.lock() {
                            *g = Some(sel.rtt().as_millis() as u64);
                        }
                        if let Ok(mut rg) = route_mon.lock() {
                            *rg = format_selected_route(sel.remote_addr());
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    // Auto-reconexão transparente para estabilidade superior ao Hamachi
                    if let Ok(mut rg) = route_mon.lock() {
                        *rg = "Reconectando P2P Direto...".to_string();
                    }
                    match tokio::time::timeout(
                        Duration::from_secs(8),
                        ep_mon.connect(remote_mon.clone(), ALPN),
                    )
                    .await
                    {
                        Ok(Ok(new_conn)) => {
                            *conn_mon.lock().await = new_conn;
                            peers_mon.store(1, Ordering::Relaxed);
                            if let Ok(mut eg) = err_mon.lock() {
                                *eg = None;
                            }
                        }
                        _ => {
                            peers_mon.store(0, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        });

        self.runtime.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let accepted = tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(250)) => continue,
                    res = listener.accept() => res,
                };
                let Ok((tcp, _)) = accepted else { break };
                let shared_conn_s = Arc::clone(&shared_conn);
                let ep_s = endpoint.clone();
                let remote_s = clean_remote.clone();
                let tx_s = Arc::clone(&bytes_tx);
                let rx_s = Arc::clone(&bytes_rx);
                let err_s = Arc::clone(&last_error);
                let peers_s = Arc::clone(&peers);

                tokio::spawn(async move {
                    let mut conn_s = { shared_conn_s.lock().await.clone() };
                    let mut stream_res = conn_s.open_bi().await;

                    // Se a conexão QUIC caiu entre tentativas do Minecraft, reconecta na hora
                    if stream_res.is_err() {
                        if let Ok(Ok(new_conn)) = tokio::time::timeout(
                            Duration::from_secs(8),
                            ep_s.connect(remote_s, ALPN),
                        )
                        .await
                        {
                            *shared_conn_s.lock().await = new_conn.clone();
                            peers_s.store(1, Ordering::Relaxed);
                            conn_s = new_conn;
                            stream_res = conn_s.open_bi().await;
                        }
                    }

                    match stream_res {
                        Ok((send, recv)) => {
                            if let Ok(mut g) = err_s.lock() {
                                *g = None;
                            }
                            relay_bidirectional(tcp, send, recv, tx_s, rx_s).await;
                        }
                        Err(e) => {
                            if let Ok(mut g) = err_s.lock() {
                                *g = Some(format!("Conexão P2P instável ou encerrada: {e}"));
                            }
                        }
                    }
                });
            }
            peers.store(0, Ordering::Relaxed);
            let final_conn = shared_conn.lock().await;
            final_conn.close(0u32.into(), b"bye");
            endpoint.close().await;
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_xor_mapped_address_parsing() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_stun_binding_request(&tx_id);
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        assert_eq!(&req[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&req[8..20], &tx_id);

        // Simula Binding Success Response (0x0101) com XOR-MAPPED-ADDRESS (0x0020)
        // para 200.150.10.25:54321
        let ip = [200u8, 150, 10, 25];
        let port: u16 = 54321;
        let xport = (port ^ 0x2112).to_be_bytes();
        let xip = [ip[0] ^ 0x21, ip[1] ^ 0x12, ip[2] ^ 0xA4, ip[3] ^ 0x42];

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x01, 0x01]); // Binding Response
        resp.extend_from_slice(&12u16.to_be_bytes()); // attr header (4) + value (8)
        resp.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        resp.extend_from_slice(&tx_id);
        // Attribute XOR-MAPPED-ADDRESS (0x0020), len = 8
        resp.extend_from_slice(&0x0020u16.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x01); // IPv4
        resp.extend_from_slice(&xport);
        resp.extend_from_slice(&xip);

        let parsed = parse_stun_binding_response(&resp, &tx_id).expect("deve extrair SocketAddr");
        assert_eq!(parsed, "200.150.10.25:54321".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_pure_p2p_tunnel_roundtrip() {
        // Inicia um servidor TCP eco local simulando o servidor Minecraft
        let mc_server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mc_port = mc_server.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = mc_server.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf) {
                    let _ = sock.write_all(&buf[..n]);
                }
            }
        });

        let host_state = TunnelState::default();
        let client_state = TunnelState::default();

        let ticket = host_state.start_host(mc_port).expect("host deve iniciar");
        let decoded = decode_ticket(&ticket).expect("ticket válido");
        assert!(
            decoded.addrs.iter().all(|a| a.is_ip()),
            "ticket não pode conter nenhum RelayUrl"
        );

        let probe_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        client_state
            .start_client(&ticket, probe_port)
            .expect("cliente P2P puro deve conectar direto ao host");

        let mut mc_client = std::net::TcpStream::connect(("127.0.0.1", probe_port)).unwrap();
        mc_client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        mc_client.write_all(b"MINECRAFT_HIT_PACKET").unwrap();
        let mut out = [0u8; 20];
        mc_client.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"MINECRAFT_HIT_PACKET");

        let st = client_state.status();
        assert!(st.active);
        assert!(st.route.contains("Direto P2P"));

        client_state.stop();
        host_state.stop();
    }
}
