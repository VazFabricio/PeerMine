use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;

const MSG_OPEN: u8 = 0x01;
const MSG_DATA: u8 = 0x02;
const MSG_CLOSE: u8 = 0x03;
const MSG_ERROR: u8 = 0x04;

#[derive(Clone, Serialize)]
pub struct BridgeInfo {
    pub port: u16,
    pub token: String,
}

struct ActiveTcpSession {
    stop: Arc<AtomicBool>,
    role: String, // "host" | "client"
    mc_port: u16,
    conns: Arc<AsyncMutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
}

pub struct TunnelState {
    runtime: tokio::runtime::Runtime,
    bridge_port: u16,
    bridge_token: String,
    ws_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    session: Arc<Mutex<Option<ActiveTcpSession>>>,
}

fn generate_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u128;
    format!("{:016x}{:08x}", nanos ^ (pid << 17), pid)
}

fn encode_frame(msg_type: u8, conn_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(msg_type);
    frame.extend_from_slice(&conn_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn decode_frame(data: &[u8]) -> Option<(u8, u32, &[u8])> {
    if data.len() < 5 {
        return None;
    }
    let msg_type = data[0];
    let conn_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    Some((msg_type, conn_id, &data[5..]))
}

fn send_ws(ws_tx: &Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>, frame: Vec<u8>) {
    if let Ok(guard) = ws_tx.lock() {
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(frame);
        }
    }
}

fn spawn_tcp_pump(
    tcp: TcpStream,
    conn_id: u32,
    ws_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    conns: Arc<AsyncMutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    stop: Arc<AtomicBool>,
) -> mpsc::Sender<Vec<u8>> {
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    // Writer: WebRTC DataChannel -> Minecraft TCP (com TCP_NODELAY)
    let stop_w = Arc::clone(&stop);
    tokio::spawn(async move {
        while !stop_w.load(Ordering::Relaxed) {
            match rx.recv().await {
                Some(data) => {
                    if tcp_w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        let _ = tcp_w.shutdown().await;
    });

    // Reader: Minecraft TCP -> WebRTC DataChannel (fatias de 16 KB para zero bufferbloat)
    let stop_r = Arc::clone(&stop);
    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            if stop_r.load(Ordering::Relaxed) {
                break;
            }
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    send_ws(&ws_tx, encode_frame(MSG_DATA, conn_id, &buf[..n]));
                }
            }
        }
        conns.lock().await.remove(&conn_id);
        send_ws(&ws_tx, encode_frame(MSG_CLOSE, conn_id, &[]));
    });

    tx
}

impl Default for TunnelState {
    fn default() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("falha ao iniciar runtime tokio");

        let listener = runtime
            .block_on(TcpListener::bind(("127.0.0.1", 0)))
            .expect("falha ao abrir bridge local");
        let bridge_port = listener.local_addr().unwrap().port();
        let bridge_token = generate_token();

        let ws_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>> = Arc::new(Mutex::new(None));
        let session: Arc<Mutex<Option<ActiveTcpSession>>> = Arc::new(Mutex::new(None));

        let token_expected = bridge_token.clone();
        let ws_tx_srv = Arc::clone(&ws_tx);
        let sess_srv = Arc::clone(&session);

        runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = stream.set_nodelay(true);
                let expected = token_expected.clone();
                let ws_tx_c = Arc::clone(&ws_tx_srv);
                let sess_c = Arc::clone(&sess_srv);

                tokio::spawn(async move {
                    let callback = |req: &Request, response: Response| {
                        let query = req.uri().query().unwrap_or("");
                        let ok = query
                            .split('&')
                            .any(|kv| kv.strip_prefix("token=") == Some(expected.as_str()));
                        if ok {
                            Ok(response)
                        } else {
                            let mut err = ErrorResponse::new(Some("Unauthorized".to_string()));
                            *err.status_mut() = StatusCode::UNAUTHORIZED;
                            Err(err)
                        }
                    };

                    let Ok(ws_stream) = tokio_tungstenite::accept_hdr_async(stream, callback).await
                    else {
                        return;
                    };

                    let (mut ws_sink, mut ws_recv) = ws_stream.split();
                    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    if let Ok(mut g) = ws_tx_c.lock() {
                        *g = Some(out_tx);
                    }

                    let writer = tokio::spawn(async move {
                        while let Some(frame) = out_rx.recv().await {
                            if ws_sink.send(Message::Binary(frame.into())).await.is_err() {
                                break;
                            }
                        }
                    });

                    while let Some(Ok(msg)) = ws_recv.next().await {
                        let Message::Binary(bytes) = msg else {
                            if msg.is_close() {
                                break;
                            }
                            continue;
                        };
                        let Some((msg_type, conn_id, payload)) = decode_frame(&bytes) else {
                            continue;
                        };

                        let active = {
                            let Ok(g) = sess_c.lock() else { continue };
                            g.as_ref().map(|s| {
                                (
                                    s.role.clone(),
                                    s.mc_port,
                                    Arc::clone(&s.conns),
                                    Arc::clone(&s.stop),
                                )
                            })
                        };
                        let Some((role, mc_port, conns, stop)) = active else {
                            continue;
                        };

                        match msg_type {
                            MSG_OPEN if role == "host" => {
                                let ws_tx_o = Arc::clone(&ws_tx_c);
                                let conns_o = Arc::clone(&conns);
                                let stop_o = Arc::clone(&stop);
                                tokio::spawn(async move {
                                    match TcpStream::connect(("127.0.0.1", mc_port)).await {
                                        Ok(tcp) => {
                                            let tx = spawn_tcp_pump(
                                                tcp,
                                                conn_id,
                                                ws_tx_o,
                                                Arc::clone(&conns_o),
                                                stop_o,
                                            );
                                            conns_o.lock().await.insert(conn_id, tx);
                                        }
                                        Err(e) => {
                                            let err_msg = format!(
                                                "Minecraft não encontrado na porta {mc_port} ({e})"
                                            );
                                            send_ws(
                                                &ws_tx_o,
                                                encode_frame(
                                                    MSG_ERROR,
                                                    conn_id,
                                                    err_msg.as_bytes(),
                                                ),
                                            );
                                            send_ws(
                                                &ws_tx_o,
                                                encode_frame(MSG_CLOSE, conn_id, &[]),
                                            );
                                        }
                                    }
                                });
                            }
                            MSG_DATA => {
                                let tx_opt = { conns.lock().await.get(&conn_id).cloned() };
                                if let Some(tx) = tx_opt {
                                    let _ = tx.send(payload.to_vec()).await;
                                }
                            }
                            MSG_CLOSE => {
                                conns.lock().await.remove(&conn_id);
                            }
                            _ => {}
                        }
                    }

                    writer.abort();
                });
            }
        });

        Self {
            runtime,
            bridge_port,
            bridge_token,
            ws_tx,
            session,
        }
    }
}

impl TunnelState {
    pub fn bridge_info(&self) -> BridgeInfo {
        BridgeInfo {
            port: self.bridge_port,
            token: self.bridge_token.clone(),
        }
    }

    pub fn stop(&self) {
        if let Ok(mut guard) = self.session.lock() {
            if let Some(sess) = guard.take() {
                sess.stop.store(true, Ordering::Relaxed);
                let conns = Arc::clone(&sess.conns);
                self.runtime.spawn(async move {
                    conns.lock().await.clear();
                });
            }
        }
    }

    pub fn start_host_tcp(&self, mc_port: u16) -> Result<(), String> {
        self.stop();
        let stop = Arc::new(AtomicBool::new(false));
        let conns = Arc::new(AsyncMutex::new(HashMap::new()));
        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(ActiveTcpSession {
                stop,
                role: "host".to_string(),
                mc_port,
                conns,
            });
        }
        Ok(())
    }

    pub fn start_client_tcp(&self, local_port: u16) -> Result<(), String> {
        self.stop();

        let listener = self
            .runtime
            .block_on(TcpListener::bind(("127.0.0.1", local_port)))
            .map_err(|e| format!("Porta local {local_port} ocupada ou bloqueada: {e}"))?;

        let stop = Arc::new(AtomicBool::new(false));
        let conns = Arc::new(AsyncMutex::new(HashMap::new()));

        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(ActiveTcpSession {
                stop: Arc::clone(&stop),
                role: "client".to_string(),
                mc_port: local_port,
                conns: Arc::clone(&conns),
            });
        }

        let ws_tx = Arc::clone(&self.ws_tx);
        let next_id = Arc::new(AtomicU32::new(1));

        self.runtime.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let accepted = tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => continue,
                    res = listener.accept() => res,
                };
                let Ok((tcp, _)) = accepted else { break };
                let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
                send_ws(&ws_tx, encode_frame(MSG_OPEN, conn_id, &[]));
                let tx = spawn_tcp_pump(
                    tcp,
                    conn_id,
                    Arc::clone(&ws_tx),
                    Arc::clone(&conns),
                    Arc::clone(&stop),
                );
                conns.lock().await.insert(conn_id, tx);
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = encode_frame(MSG_DATA, 42, b"MC_PACKET");
        let (t, id, payload) = decode_frame(&frame).unwrap();
        assert_eq!(t, MSG_DATA);
        assert_eq!(id, 42);
        assert_eq!(payload, b"MC_PACKET");
    }

    #[test]
    fn test_local_bridge_tcp_roundtrip() {
        let mc_server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mc_port = mc_server.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut sock, _)) = mc_server.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf) {
                    let _ = sock.write_all(&buf[..n]);
                }
            }
        });

        let host_state = TunnelState::default();
        let info = host_state.bridge_info();
        assert!(info.port > 0);
        assert!(!info.token.is_empty());
        host_state.start_host_tcp(mc_port).unwrap();
        host_state.stop();
    }
}
