//! Running the agent (and scheduled backups) as login services.
//! macOS: launchd user agents in the GUI session, so Touch ID can prompt.
//! Linux: systemd user units.

use std::path::PathBuf;
use std::process::Command;

use crate::error::{invalid, Error, Result};
use crate::{paths, ui};

const AGENT: &str = "dev.thepit.agent";
const BACKUP: &str = "dev.thepit.backup";

fn launch_agents() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join("Library/LaunchAgents")
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist(label: &str, args: &[String], keep_alive: bool, interval: Option<u64>) -> String {
    let args_xml: String = args
        .iter()
        .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
        .collect();
    let mut env = format!(
        "    <key>PATH</key><string>{}</string>\n",
        xml_escape(&paths::tool_path())
    );
    if let Ok(h) = std::env::var("PIT_HOME") {
        env.push_str(&format!(
            "    <key>PIT_HOME</key><string>{}</string>\n",
            xml_escape(&h)
        ));
    }
    let extra = match interval {
        Some(s) => format!("  <key>StartInterval</key><integer>{s}</integer>\n"),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args_xml}  </array>
  <key>EnvironmentVariables</key>
  <dict>
{env}  </dict>
  <key>RunAtLoad</key><{}/>
  <key>KeepAlive</key><{}/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardErrorPath</key><string>{}</string>
{extra}</dict>
</plist>
"#,
        if keep_alive { "true" } else { "false" },
        if keep_alive { "true" } else { "false" },
        xml_escape(
            &paths::state_dir()
                .join(format!("{label}.log"))
                .display()
                .to_string()
        ),
    )
}

fn load(label: &str, path: &PathBuf) -> Result<()> {
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("gui/{}/{label}", uid())])
        .output();
    let out = Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{}", uid())])
        .arg(path)
        .output()?;
    if !out.status.success() {
        return Err(Error::Invalid(format!(
            "launchctl could not load {label}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn unload(label: &str) {
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("gui/{}/{label}", uid())])
        .output();
}

pub fn installed() -> bool {
    if cfg!(target_os = "macos") {
        launch_agents().join(format!("{AGENT}.plist")).exists()
    } else {
        systemd_dir().join("the-pit-agent.service").exists()
    }
}

fn systemd_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_default().join("systemd/user")
}

pub fn cmd(action: &str) -> Result<()> {
    let exe = paths::self_exe().display().to_string();
    match action {
        "install" => {
            paths::ensure_layout()?;
            if crate::protocol::agent_running() {
                let _ = crate::protocol::call("cli", "shutdown", serde_json::json!({}), None);
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            if cfg!(target_os = "macos") {
                std::fs::create_dir_all(launch_agents())?;
                let p = launch_agents().join(format!("{AGENT}.plist"));
                std::fs::write(&p, plist(AGENT, &[exe, "agent".into()], true, None))?;
                load(AGENT, &p)?;
                ui::ok(&format!("the agent starts at login ({})", p.display()));
                if crate::backup::Config::load()
                    .map(|c| c.auto)
                    .unwrap_or(true)
                {
                    backup_catchup(true)?;
                    ui::ok("backups follow every change, with a catch-up check every 15 min");
                }
            } else {
                std::fs::create_dir_all(systemd_dir())?;
                let p = systemd_dir().join("the-pit-agent.service");
                std::fs::write(&p, format!("[Unit]\nDescription=The Pit agent\n\n[Service]\nExecStart={exe} agent\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n"))?;
                Command::new("systemctl")
                    .args(["--user", "daemon-reload"])
                    .status()?;
                Command::new("systemctl")
                    .args(["--user", "enable", "--now", "the-pit-agent.service"])
                    .status()?;
                ui::ok(&format!("the agent starts at login ({})", p.display()));
                if crate::backup::Config::load()
                    .map(|c| c.auto)
                    .unwrap_or(true)
                {
                    backup_catchup(true)?;
                    ui::ok("backups follow every change, with a catch-up check every 15 min");
                }
            }
            Ok(())
        }
        "uninstall" => {
            if cfg!(target_os = "macos") {
                unload(AGENT);
                let _ = std::fs::remove_file(launch_agents().join(format!("{AGENT}.plist")));
            } else {
                let _ = Command::new("systemctl")
                    .args(["--user", "disable", "--now", "the-pit-agent.service"])
                    .status();
                let _ = std::fs::remove_file(systemd_dir().join("the-pit-agent.service"));
            }
            let _ = backup_catchup(false);
            ui::ok("the agent no longer starts at login");
            Ok(())
        }
        "status" => {
            println!(
                "login service: {}",
                if installed() {
                    "installed"
                } else {
                    "not installed"
                }
            );
            println!(
                "agent: {}",
                if crate::protocol::agent_running() {
                    "running"
                } else {
                    "not running"
                }
            );
            Ok(())
        }
        "restart" => {
            if crate::protocol::agent_running() {
                let _ = crate::protocol::call("cli", "shutdown", serde_json::json!({}), None);
            }
            if installed() && cfg!(target_os = "macos") {
                let _ = Command::new("launchctl")
                    .args(["kickstart", "-k", &format!("gui/{}/{AGENT}", uid())])
                    .status();
            } else {
                crate::protocol::ensure_agent()?;
            }
            ui::ok("agent restarted (locked)");
            Ok(())
        }
        _ => invalid("use: pit service install | uninstall | status | restart"),
    }
}

pub fn catchup_installed() -> bool {
    if cfg!(target_os = "macos") {
        launch_agents().join(format!("{BACKUP}.plist")).exists()
    } else {
        systemd_dir().join("the-pit-backup.timer").exists()
    }
}

/// A light check every 15 minutes (and on wake) that sends any backup still
/// owed — for when the agent is not running. It does nothing when every target
/// is up to date.
pub fn backup_catchup(on: bool) -> Result<()> {
    let exe = paths::self_exe().display().to_string();
    if cfg!(target_os = "macos") {
        let p = launch_agents().join(format!("{BACKUP}.plist"));
        unload(BACKUP);
        if !on {
            let _ = std::fs::remove_file(&p);
            return Ok(());
        }
        std::fs::create_dir_all(launch_agents())?;
        std::fs::write(
            &p,
            plist(
                BACKUP,
                &[exe, "backup".into(), "sync".into(), "--quiet".into()],
                false,
                Some(15 * 60),
            ),
        )?;
        load(BACKUP, &p)
    } else {
        let dir = systemd_dir();
        if !on {
            let _ = Command::new("systemctl")
                .args(["--user", "disable", "--now", "the-pit-backup.timer"])
                .status();
            let _ = std::fs::remove_file(dir.join("the-pit-backup.timer"));
            let _ = std::fs::remove_file(dir.join("the-pit-backup.service"));
            return Ok(());
        }
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("the-pit-backup.service"), format!("[Unit]\nDescription=The Pit: send any backup still owed\n\n[Service]\nType=oneshot\nExecStart={exe} backup sync --quiet\n"))?;
        std::fs::write(dir.join("the-pit-backup.timer"), "[Unit]\nDescription=The Pit backup catch-up\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=15min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")?;
        Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        Command::new("systemctl")
            .args(["--user", "enable", "--now", "the-pit-backup.timer"])
            .status()?;
        Ok(())
    }
}
