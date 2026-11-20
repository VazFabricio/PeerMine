mod tunnel;

use tauri::State;
use tunnel::{BridgeInfo, TunnelState};

#[tauri::command]
fn get_bridge_info(state: State<'_, TunnelState>) -> BridgeInfo {
    state.bridge_info()
}

#[tauri::command]
fn start_host_tcp(state: State<'_, TunnelState>, mc_port: u16) -> Result<(), String> {
    state.start_host_tcp(mc_port)
}

#[tauri::command]
fn start_client_tcp(state: State<'_, TunnelState>, local_port: u16) -> Result<(), String> {
    state.start_client_tcp(local_port)
}

#[tauri::command]
fn stop_tunnel(state: State<'_, TunnelState>) {
    state.stop();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TunnelState::default())
        .invoke_handler(tauri::generate_handler![
            get_bridge_info,
            start_host_tcp,
            start_client_tcp,
            stop_tunnel
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o PeerMine");
}
