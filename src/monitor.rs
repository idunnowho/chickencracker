use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

pub struct MonitorHandle {
    pub interface: String,
    pub original: String,
    pub was_already_monitor: bool,
}

pub fn require_root() -> Result<()> {
    if !is_root() {
        bail!(
            "root privileges required. Run with: sudo {}",
            std::env::args().next().unwrap_or_else(|| "chickencracker".into())
        );
    }
    Ok(())
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Strip airmon-ng's `mon` suffix to get the base interface (wlan0mon → wlan0).
pub fn base_interface_name(iface: &str) -> String {
    if let Some(base) = iface.strip_suffix("mon") {
        if interface_exists(base) || !interface_exists(iface) {
            return base.to_string();
        }
    }
    iface.to_string()
}

pub fn enable_monitor_modes(adapters: &[&crate::adapter::WifiAdapter]) -> Result<Vec<MonitorHandle>> {
    println!("\n{}", "═══ Enabling Monitor Mode ═══".bold().cyan());
    kill_interfering_processes()?;

    let mut handles = Vec::new();
    for adapter in adapters {
        let setup_iface = if adapter.already_monitor() {
            adapter.name.clone()
        } else {
            adapter.base_name()
        };

        match enable_monitor_mode_inner(&setup_iface) {
            Ok(handle) => handles.push(handle),
            Err(e) => {
                println!(
                    "  {} Failed on {}: {e:#}",
                    "✗".red(),
                    adapter.name
                );
            }
        }
    }

    if handles.is_empty() {
        bail!("failed to enable monitor mode on any adapter");
    }

    Ok(handles)
}

pub fn enable_monitor_mode(iface: &str) -> Result<MonitorHandle> {
    println!("\n{}", "═══ Enabling Monitor Mode ═══".bold().cyan());
    kill_interfering_processes()?;
    enable_monitor_mode_inner(iface)
}

fn enable_monitor_mode_inner(iface: &str) -> Result<MonitorHandle> {
    // Already in monitor mode — use as-is, don't run airmon-ng again
    if interface_exists(iface) {
        let mode = get_interface_mode(iface)?;
        if mode == "monitor" {
            let original = base_interface_name(iface);
            println!(
                "  {} {} already in {} mode — skipping setup",
                "✓".green(),
                iface.bold(),
                "monitor".green().bold()
            );
            return Ok(MonitorHandle {
                interface: iface.to_string(),
                original,
                was_already_monitor: true,
            });
        }
    }

    // Never run airmon-ng on an existing mon vif — use the base interface
    let base = base_interface_name(iface);
    let setup_iface = if interface_exists(&base) {
        &base
    } else {
        iface
    };

    if setup_iface != iface {
        println!(
            "  {} Using base interface {} (not {})",
            "→".cyan(),
            setup_iface.bold(),
            iface.dimmed()
        );
    }

    let mon_iface = try_airmon(setup_iface).or_else(|_| try_iw_monitor(setup_iface))?;

    thread::sleep(Duration::from_secs(2));

    let mode = get_interface_mode(&mon_iface)?;
    if mode != "monitor" {
        bail!("failed to set monitor mode on {mon_iface} (current mode: {mode})");
    }

    println!(
        "  {} {} is now in {} mode",
        "✓".green(),
        mon_iface.bold(),
        "monitor".green().bold()
    );

    Ok(MonitorHandle {
        interface: mon_iface,
        original: setup_iface.to_string(),
        was_already_monitor: false,
    })
}

fn kill_interfering_processes() -> Result<()> {
    println!("  {} Stopping interfering processes...", "…".yellow());

    let output = Command::new("airmon-ng")
        .args(["check", "kill"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match output {
        Ok(status) if status.success() => {
            println!("  {} NetworkManager/processes stopped", "✓".green());
        }
        _ => {
            let _ = Command::new("systemctl")
                .args(["stop", "NetworkManager"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("service")
                .args(["network-manager", "stop"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            println!(
                "  {} Attempted to stop interfering services",
                "⚠".yellow()
            );
        }
    }

    thread::sleep(Duration::from_secs(1));
    Ok(())
}

fn try_airmon(iface: &str) -> Result<String> {
    println!("  {} Starting monitor mode via airmon-ng...", "…".yellow());

    let output = Command::new("airmon-ng")
        .args(["start", iface])
        .output()
        .context("failed to run airmon-ng")?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if combined.contains("monitor mode enabled") || combined.contains("monitor mode vif enabled") {
        if let Some(mon) = extract_mon_iface(&combined, iface) {
            return Ok(mon);
        }
    }

    // Check if airmon created wlan0mon while leaving wlan0
    let candidate = format!("{iface}mon");
    if interface_exists(&candidate) && get_interface_mode(&candidate)? == "monitor" {
        return Ok(candidate);
    }

    // iw set type monitor keeps the same interface name
    if get_interface_mode(iface)? == "monitor" {
        return Ok(iface.to_string());
    }

    if output.status.success() {
        return Ok(candidate);
    }

    Err(anyhow::anyhow!("airmon-ng failed: {combined}"))
}

fn extract_mon_iface(output: &str, original: &str) -> Option<String> {
    // airmon-ng output: "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)"
    for line in output.lines() {
        if line.contains("monitor mode") {
            if let Some(start) = line.rfind(']') {
                let rest = &line[start + 1..];
                let name = rest.trim().trim_end_matches(')').trim();
                if !name.is_empty() && interface_exists(name) {
                    return Some(name.to_string());
                }
            }
        }
    }

    let candidate = format!("{original}mon");
    if interface_exists(&candidate) {
        return Some(candidate);
    }

    None
}

fn try_iw_monitor(iface: &str) -> Result<String> {
    println!("  {} Falling back to iw monitor mode...", "…".yellow());

    Command::new("ip")
        .args(["link", "set", iface, "down"])
        .status()
        .context("failed to bring interface down")?;

    let status = Command::new("iw")
        .args(["dev", iface, "set", "type", "monitor"])
        .status()
        .context("failed to run iw set type monitor")?;

    if !status.success() {
        bail!("iw set type monitor failed");
    }

    Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status()
        .context("failed to bring interface up")?;

    Ok(iface.to_string())
}

pub fn interface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

fn get_interface_mode(iface: &str) -> Result<String> {
    if !interface_exists(iface) {
        return Ok(String::from("unknown"));
    }

    let output = Command::new("iw")
        .args(["dev", iface, "info"])
        .output()
        .with_context(|| format!("failed to query {iface}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.trim().starts_with("type ") {
            return Ok(line.split_whitespace().nth(1).unwrap_or("unknown").to_string());
        }
    }
    Ok(String::from("unknown"))
}

pub fn restore_managed_mode(handles: &[MonitorHandle]) {
    for handle in handles {
        restore_one(handle);
    }
}

fn restore_one(handle: &MonitorHandle) {
    println!(
        "\n  {} Restoring {} to managed mode...",
        "…".dimmed(),
        handle.original
    );

    let _ = Command::new("airmon-ng")
        .args(["stop", &handle.interface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let restore_iface = if interface_exists(&handle.original) {
        handle.original.clone()
    } else {
        handle.interface.clone()
    };

    let _ = Command::new("ip")
        .args(["link", "set", &restore_iface, "down"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = Command::new("iw")
        .args(["dev", &restore_iface, "set", "type", "managed"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = Command::new("ip")
        .args(["link", "set", &restore_iface, "up"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = Command::new("systemctl")
        .args(["start", "NetworkManager"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    println!(
        "  {} {} back in managed mode",
        "✓".green(),
        restore_iface.bold()
    );
}
