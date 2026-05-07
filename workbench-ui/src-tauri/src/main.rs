#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::process::Command;

#[tauri::command]
fn run_shutterwall(cmd: String) -> String {
    // SHUTTERWALL_TRUST_SET_GATE_V1
let trust_set_allowed = cmd.starts_with("trust-set ")
    && (cmd.ends_with(" trusted") || cmd.ends_with(" review") || cmd.ends_with(" blocked") || cmd.ends_with(" unknown"));

let allowed = ["quickstart","inspect","baseline","diff","identity","registry","posture","watch 1","scan","apply","undo","doctor","version"];
    if !trust_set_allowed && !allowed.contains(&cmd.as_str()) { return format!("DENIED_COMMAND: {}", cmd); }
    let command_text = format!("shutterwall {}", cmd);
    let output = Command::new("powershell.exe").args(["-NoProfile","-ExecutionPolicy","Bypass","-Command",&command_text]).output();
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if stderr.trim().is_empty() { stdout } else { format!("{}\\n{}", stdout, stderr) }
        }
        Err(e) => format!("SHUTTERWALL_UI_COMMAND_ERROR: {}", e),
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_shutterwall])
        .run(tauri::generate_context!())
        .expect("error while running ShutterWall");
}



