mod tunnel;

use tauri::State;
use tunnel::{TunnelState, TunnelStatus};

#[tauri::command]
fn start_host(state: State<'_, TunnelState>, mc_port: u16) -> Result<String, String> {
    state.start_host(mc_port)
}

#[tauri::command]
fn start_client(
    state: State<'_, TunnelState>,
    ticket: String,
    local_port: u16,
) -> Result<(), String> {
    state.start_client(&ticket, local_port)
}

#[tauri::command]
fn stop_tunnel(state: State<'_, TunnelState>) {
    state.stop();
}

#[tauri::command]
fn get_status(state: State<'_, TunnelState>) -> TunnelStatus {
    state.status()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TunnelState::default())
        .invoke_handler(tauri::generate_handler![
            start_host,
            start_client,
            stop_tunnel,
            get_status
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o PeerMine");
}
