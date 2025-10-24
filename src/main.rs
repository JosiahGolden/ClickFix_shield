#![windows_subsystem = "windows"]

use tray_icon::Icon;
use tao::event_loop::{ControlFlow, EventLoopBuilder};

use clipboard_win::{formats, get_clipboard, set_clipboard};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use time::OffsetDateTime;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};

use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
     TrayIconBuilder,
};

static DEFAULT_PATTERNS: &[&str] = &[
    r"(?i)\b(powershell(\.exe)?|cmd\.exe|mshta(\.exe)?|rundll32(\.exe)?|regsvr32(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|bitsadmin(\.exe)?|certutil(\.exe)?|wmic(\.exe)?)\b",
    r"(?i)\bInvoke-Expression\b|\bIEX\b|\bFromBase64String\b|\bDownloadString\b|\bNew-Object\s+Net\.WebClient\b",
    r"(?i)^\s*powershell\s+",
    r"(?i)^\s*cmd\s*/c\s+",
    r"(?i)\b(Set|Add)-MpPreference\b|\b-Exclusion(Path|Process|Extension)\b",
    r"(?i)[A-Za-z0-9+/]{40,}={0,2}\s*$",
];

static SUSPICIOUS: Lazy<Regex> = Lazy::new(|| {
    let joined = DEFAULT_PATTERNS.join("|");
    Regex::new(&joined).expect("invalid regex")
});

#[derive(Serialize, Deserialize, Default, Clone)]
struct Config {
    allow_regex: Vec<String>,
    poll_ms: Option<u64>,
}

fn program_data_dir() -> PathBuf {
    // Force ProgramData for consistent logs/config
    let dir = PathBuf::from(r"C:\ProgramData\ClickfixShield");
    dir
}
fn config_path() -> PathBuf {
    let mut p = program_data_dir();
    p.push("config.json");
    p
}
fn log_path() -> PathBuf {
    let mut p = program_data_dir();
    p.push("shield.log");
    p
}

fn load_config() -> Config {
    let path = config_path();
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(cfg) = serde_json::from_slice::<Config>(&bytes) {
            return cfg;
        }
    }
    let default = Config {
        allow_regex: vec![],
        poll_ms: Some(300),
    };
    let _ = fs::create_dir_all(program_data_dir());
    let _ = fs::write(&path, serde_json::to_vec_pretty(&default).unwrap());
    default
}

fn append_log(line: &str) {
    let _ = fs::create_dir_all(program_data_dir());
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
        .unwrap_or_else(|_| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open("shield.log")
                .expect("cannot open log")
        });
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "now".to_string());
    let _ = writeln!(f, "{} {}", timestamp, line);
}

fn wstr(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn alert(msg: &str) {
    unsafe {
        let title = wstr("ClickFix Shield");
        let body = wstr(msg);
        MessageBoxW(
            HWND(0),
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONWARNING,
        );
    }
}

fn open_with_shell(path: &str) {
    unsafe {
        let op = wstr("open");
        let file = wstr(path);
        ShellExecuteW(
            HWND(0),
            PCWSTR(op.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(std::ptr::null()),
            PCWSTR(std::ptr::null()),
            SW_SHOWNORMAL,
        );
    }
}

fn get_text_clipboard() -> Result<String, String> {
    get_clipboard(formats::Unicode).map_err(|e| format!("{e:?}"))
}

fn start_clipboard_watcher(paused: Arc<AtomicBool>, cfg: Config) {
    let allow_res: Vec<Regex> = cfg
        .allow_regex
        .iter()
        .filter_map(|r| Regex::new(r).ok())
        .collect();
    let poll = Duration::from_millis(cfg.poll_ms.unwrap_or(300));
    let mut last_seen: Option<String> = None;

    thread::spawn(move || loop {
        if !paused.load(Ordering::Relaxed) {
            if let Ok(text) = get_text_clipboard() {
                if last_seen.as_deref() != Some(&text) {
                    last_seen = Some(text.clone());
                    let allowed = allow_res.iter().any(|r| r.is_match(&text));
                    let suspicious = SUSPICIOUS.is_match(&text);
                    if suspicious && !allowed {
                        let _ = set_clipboard(formats::Unicode, "");
                        append_log(&format!(
                            "BLOCKED clipboard content ({} chars)",
                            text.chars().count()
                        ));
                        alert("Suspicious clipboard content was blocked and cleared.");
                    }
                }
            }
        }
        thread::sleep(poll);
    });
}

fn main() {
    // Ensure data dir exists and config/log files are ready
    let _ = fs::create_dir_all(program_data_dir());
    let cfg = load_config();
    append_log("ClickFix Shield starting (tray mode)…");

    // Shared pause flag
    let paused = Arc::new(AtomicBool::new(false));
    start_clipboard_watcher(paused.clone(), cfg.clone());

    // --- Build tray menu ---
    let menu = Menu::new();

    let pause_item = MenuItem::new("Pause", true, None);
    let resume_item = MenuItem::new("Resume", true, None);
    resume_item.set_enabled(false); // start unpaused

    let open_log = MenuItem::new("Open Log", true, None);
    let open_cfg = MenuItem::new("Open Config", true, None);
    let sep = PredefinedMenuItem::separator();
    let quit = MenuItem::new("Exit", true, None);



    menu.append(&pause_item).unwrap();
    menu.append(&resume_item).unwrap();
    menu.append(&open_log).unwrap();
    menu.append(&open_cfg).unwrap();
    menu.append(&sep).unwrap();
    menu.append(&quit).unwrap();

    
    // --- Tray icon ---
    let icon = Icon::from_resource(1, None).unwrap_or_else(|_| {
        // fallback to file path if resource id differs
        tray_icon::Icon::from_path("assets\\icon.ico", None).expect("failed to load icon")
    });

    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("ClickFix Shield")
        .with_icon(icon)
        .build()
        .expect("tray icon");

    // Receiver for menu clicks
    let event_rx = MenuEvent::receiver();


    let event_loop = EventLoopBuilder::<()>::new().build();

    event_loop.run(move |_, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        // Drain any pending menu clicks
        while let Ok(event) = event_rx.try_recv() {
            if event.id == pause_item.id() {
                paused.store(true, Ordering::Relaxed);
                pause_item.set_enabled(false);
                resume_item.set_enabled(true);
                append_log("Paused by user from tray.");
            } else if event.id == resume_item.id() {
                paused.store(false, Ordering::Relaxed);
                resume_item.set_enabled(false);
                pause_item.set_enabled(true);
                append_log("Resumed by user from tray.");
            } else if event.id == open_log.id() {
                open_with_shell(&log_path().to_string_lossy());
            } else if event.id == open_cfg.id() {
                open_with_shell(&config_path().to_string_lossy());
            } else if event.id == quit.id() {
                append_log("Exiting by user request.");
                *control_flow = ControlFlow::Exit; // exit cleanly
            }
        }
    });


}
