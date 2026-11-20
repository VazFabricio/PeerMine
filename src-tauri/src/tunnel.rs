use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use iroh::endpoint::QuicTransportConfig;
use iroh::{Endpoint, EndpointAddr};
use serde::Serialize;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ALPN: &[u8] = b"peermine/1";

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

fn low_latency_transport() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .keep_alive_interval(std::time::Duration::from_secs(3))
        .build()
}

async fn relay_bidirectional(
    tcp: TcpStream,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
) {
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    let t1 = async {
        let mut buf = [0u8; 64 * 1024];
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
        let mut buf = [0u8; 64 * 1024];
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

        let endpoint = self
            .runtime
            .block_on(async {
                Endpoint::builder(iroh::endpoint::presets::N0)
                    .transport_config(low_latency_transport())
                    .alpns(vec![ALPN.to_vec()])
                    .bind()
                    .await
            })
            .map_err(|e| format!("Erro ao criar endpoint P2P: {e}"))?;

        // Aguarda descobrir endereços diretos/relay antes de gerar o código PM1:
        let addr = self.runtime.block_on(async {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(4), endpoint.online()).await;
            endpoint.addr()
        });

        let ticket = encode_ticket(&addr)?;
        let stop = Arc::new(AtomicBool::new(false));
        let peers = Arc::new(AtomicUsize::new(0));
        let bytes_tx = Arc::new(AtomicU64::new(0));
        let bytes_rx = Arc::new(AtomicU64::new(0));
        let route = Arc::new(Mutex::new("Aguardando jogadores...".to_string()));
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
                    _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
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
                        *g = "Conectado P2P (QUIC)".to_string();
                    }

                    // Monitora RTT e rota do colega
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
                                    *rg = if sel.is_ip() {
                                        "Direto P2P (UDP)".to_string()
                                    } else {
                                        "Relay P2P".to_string()
                                    };
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    });

                    while !stop_c.load(Ordering::Relaxed) {
                        let stream = tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
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

        let (endpoint, conn, listener) = self.runtime.block_on(async {
            let listener = TcpListener::bind(("127.0.0.1", local_port))
                .await
                .map_err(|e| format!("Porta local {local_port} ocupada ou bloqueada: {e}"))?;

            let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
                .transport_config(low_latency_transport())
                .bind()
                .await
                .map_err(|e| format!("Erro ao iniciar cliente P2P: {e}"))?;

            let conn = tokio::time::timeout(
                std::time::Duration::from_secs(12),
                endpoint.connect(remote_addr, ALPN),
            )
            .await
            .map_err(|_| "Timeout ao conectar ao Host P2P".to_string())?
            .map_err(|e| format!("Falha ao conectar ao Host: {e}"))?;

            Ok::<_, String>((endpoint, conn, listener))
        })?;

        let stop = Arc::new(AtomicBool::new(false));
        let peers = Arc::new(AtomicUsize::new(1));
        let bytes_tx = Arc::new(AtomicU64::new(0));
        let bytes_rx = Arc::new(AtomicU64::new(0));
        let route = Arc::new(Mutex::new("Conectado P2P (QUIC)".to_string()));
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

        // Monitora RTT e se a rota é Direta P2P ou Relay
        let conn_mon = conn.clone();
        let stop_mon = Arc::clone(&stop);
        let route_mon = Arc::clone(&route);
        let rtt_mon = Arc::clone(&rtt_ms);
        self.runtime.spawn(async move {
            while !stop_mon.load(Ordering::Relaxed) && conn_mon.close_reason().is_none() {
                let paths = conn_mon.paths();
                if let Some(sel) = paths.iter().find(|x| x.is_selected()) {
                    if let Ok(mut g) = rtt_mon.lock() {
                        *g = Some(sel.rtt().as_millis() as u64);
                    }
                    if let Ok(mut rg) = route_mon.lock() {
                        *rg = if sel.is_ip() {
                            "Direto P2P (UDP)".to_string()
                        } else {
                            "Relay P2P".to_string()
                        };
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        self.runtime.spawn(async move {
            while !stop.load(Ordering::Relaxed) && conn.close_reason().is_none() {
                let accepted = tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => continue,
                    res = listener.accept() => res,
                };
                let Ok((tcp, _)) = accepted else { break };
                let conn_s = conn.clone();
                let tx_s = Arc::clone(&bytes_tx);
                let rx_s = Arc::clone(&bytes_rx);
                let err_s = Arc::clone(&last_error);

                tokio::spawn(async move {
                    match conn_s.open_bi().await {
                        Ok((send, recv)) => relay_bidirectional(tcp, send, recv, tx_s, rx_s).await,
                        Err(e) => {
                            if let Ok(mut g) = err_s.lock() {
                                *g = Some(format!("Conexão P2P encerrada: {e}"));
                            }
                        }
                    }
                });
            }
            peers.store(0, Ordering::Relaxed);
            conn.close(0u32.into(), b"bye");
            endpoint.close().await;
        });

        Ok(())
    }
}
