use crate::quit;
use crate::security::{SecurityType, Vulnerability};
use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct WifiNetwork {
    pub bssid: String,
    pub essid: String,
    pub channel: u8,
    pub power: i32,
    pub security: SecurityType,
    pub vulnerability: Vulnerability,
    pub cipher: String,
    pub auth: String,
    pub clients: Vec<String>,
}

pub fn scan_networks_multi(
    ifaces: &[&str],
    duration_secs: u64,
    output_dir: &Path,
) -> Result<Vec<WifiNetwork>> {
    if ifaces.len() == 1 {
        return scan_networks(ifaces[0], duration_secs, output_dir);
    }

    println!("\n{}", "═══ Scanning for WiFi Networks ═══".bold().cyan());
    println!(
        "  {} Listening on {} for {}s each...\n",
        "…".yellow(),
        ifaces.join(", ").bold(),
        duration_secs
    );

    let mut all_networks = Vec::new();

    for iface in ifaces {
        let iface_dir = output_dir.join(sanitize_iface(iface));
        fs::create_dir_all(&iface_dir).context("failed to create scan output directory")?;

        println!("  {} Scanning on {}...", "→".cyan(), iface.bold());
        match scan_networks_quiet(iface, duration_secs, &iface_dir) {
            Ok(nets) => {
                println!("      Found {} network(s) on {}", nets.len(), iface);
                all_networks.push(nets);
            }
            Err(e) => {
                println!("      {} Scan on {} failed: {e:#}", "✗".red(), iface);
            }
        }
    }

    let merged = merge_networks(all_networks);
    Ok(merged)
}

fn sanitize_iface(iface: &str) -> String {
    iface.replace('/', "_")
}

fn scan_networks_quiet(iface: &str, duration_secs: u64, output_dir: &Path) -> Result<Vec<WifiNetwork>> {
    fs::create_dir_all(output_dir).context("failed to create scan output directory")?;
    clear_old_scans(output_dir)?;

    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let prefix = output_dir.join(format!("scan_{stamp}"));
    let prefix_str = prefix.to_string_lossy();
    let scan_started = std::time::SystemTime::now();

    let mut child = Command::new("airodump-ng")
        .args([
            "--write",
            &prefix_str,
            "--output-format",
            "csv,pcap",
            "--write-interval",
            "1",
            "--ignore-negative-one",
            iface,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start airodump-ng")?;

    quit::track_pid(child.id());
    let pid = child.id();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(duration_secs) {
        if quit::sleep(Duration::from_secs(1)).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            quit::untrack_pid(pid);
            quit::abort_if()?;
            break;
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    quit::untrack_pid(pid);
    thread::sleep(Duration::from_millis(500));

    let csv_path = find_scan_csv(output_dir, &format!("scan_{stamp}"), scan_started)?;
    let networks = parse_airodump_csv(&csv_path)?;

    if networks.is_empty() {
        return scan_with_iw(iface);
    }

    Ok(networks)
}

fn merge_networks(scans: Vec<Vec<WifiNetwork>>) -> Vec<WifiNetwork> {
    use std::collections::HashMap;

    let mut by_bssid: HashMap<String, WifiNetwork> = HashMap::new();

    for networks in scans {
        for net in networks {
            by_bssid
                .entry(net.bssid.clone())
                .and_modify(|existing| {
                    if net.power > existing.power {
                        *existing = net.clone();
                    }
                })
                .or_insert(net);
        }
    }

    let mut merged: Vec<_> = by_bssid.into_values().collect();
    merged.sort_by(|a, b| b.power.cmp(&a.power));
    merged
}

pub fn scan_networks(iface: &str, duration_secs: u64, output_dir: &Path) -> Result<Vec<WifiNetwork>> {
    println!("\n{}", "═══ Scanning for WiFi Networks ═══".bold().cyan());
    println!(
        "  {} Listening on {} for {}s...\n",
        "…".yellow(),
        iface.bold(),
        duration_secs
    );

    fs::create_dir_all(output_dir).context("failed to create scan output directory")?;
    clear_old_scans(output_dir)?;

    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let prefix = output_dir.join(format!("scan_{stamp}"));
    let prefix_str = prefix.to_string_lossy();
    let scan_started = std::time::SystemTime::now();

    let mut child = Command::new("airodump-ng")
        .args([
            "--write",
            &prefix_str,
            "--output-format",
            "csv,pcap",
            "--write-interval",
            "1",
            "--ignore-negative-one",
            iface,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start airodump-ng — is aircrack-ng installed?")?;

    quit::track_pid(child.id());
    let pid = child.id();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(duration_secs) {
        // Bail early if airodump died (bad iface, rfkill, etc.)
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut buf = String::new();
                        let _ = std::io::Read::read_to_string(&mut s, &mut buf);
                        buf
                    })
                    .unwrap_or_default();
                quit::untrack_pid(pid);
                anyhow::bail!(
                    "airodump-ng exited early ({status}). {}",
                    stderr.trim().lines().last().unwrap_or("check interface / rfkill")
                );
            }
            Ok(None) => {}
            Err(_) => {}
        }

        if quit::sleep(Duration::from_secs(1)).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            quit::untrack_pid(pid);
            quit::abort_if()?;
            break;
        }
        let elapsed = start.elapsed().as_secs();
        print!(
            "\r  Scanning... {}s / {}s  ({})",
            elapsed,
            duration_secs,
            quit::hint().dimmed()
        );
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }
    println!();

    let _ = child.kill();
    let _ = child.wait();
    quit::untrack_pid(pid);

    thread::sleep(Duration::from_millis(500));

    let csv_path = find_scan_csv(output_dir, &format!("scan_{stamp}"), scan_started)?;
    println!(
        "  {} Using fresh capture: {}",
        "→".cyan(),
        csv_path.file_name().unwrap_or_default().to_string_lossy()
    );

    let networks = parse_airodump_csv(&csv_path)?;

    if networks.is_empty() {
        println!(
            "  {} No networks in this capture — trying live iw scan...",
            "⚠".yellow()
        );
        return scan_with_iw(iface);
    }

    Ok(networks)
}

fn clear_old_scans(output_dir: &Path) -> Result<()> {
    let Ok(entries) = fs::read_dir(output_dir) else {
        return Ok(());
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.starts_with("scan") {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

fn find_scan_csv(output_dir: &Path, prefix: &str, not_before: std::time::SystemTime) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = fs::read_dir(output_dir)
        .context("failed to read scan output directory")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            p.extension().map(|e| e == "csv").unwrap_or(false)
                && name.starts_with(prefix)
                && fs::metadata(p)
                    .and_then(|m| m.modified())
                    .map(|t| t >= not_before - Duration::from_secs(2))
                    .unwrap_or(false)
        })
        .collect();

    candidates.sort_by_key(|p| {
        fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
    });

    candidates.pop().with_context(|| {
        format!(
            "no fresh scan CSV for this run in {} — airodump may have failed (wrong iface, rfkill, or not in monitor mode)",
            output_dir.display()
        )
    })
}

pub fn parse_airodump_csv(path: &Path) -> Result<Vec<WifiNetwork>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut networks = Vec::new();
    let mut stations: Vec<(String, String)> = Vec::new();
    let mut in_ap_section = false;
    let mut in_sta_section = false;

    for line in content.lines() {
        if line.starts_with("BSSID") {
            in_ap_section = true;
            in_sta_section = false;
            continue;
        }
        if line.starts_with("Station MAC") {
            in_ap_section = false;
            in_sta_section = true;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }

        if in_ap_section {
            if let Some(net) = parse_csv_line(line) {
                networks.push(net);
            }
        } else if in_sta_section {
            if let Some((sta, bssid)) = parse_station_line(line) {
                stations.push((sta, bssid));
            }
        }
    }

    for (sta, bssid) in stations {
        if let Some(net) = networks.iter_mut().find(|n| n.bssid.eq_ignore_ascii_case(&bssid)) {
            if !net.clients.iter().any(|c| c.eq_ignore_ascii_case(&sta)) {
                net.clients.push(sta);
            }
        }
    }

    networks.sort_by(|a, b| b.power.cmp(&a.power));
    networks.dedup_by(|a, b| a.bssid == b.bssid);
    Ok(networks)
}

fn parse_station_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 6 {
        return None;
    }
    let sta = parts[0].trim().to_string();
    let bssid = parts[5].trim().to_string();
    if !sta.contains(':') || sta.len() < 17 {
        return None;
    }
    if bssid.contains("not associated") || !bssid.contains(':') {
        return None;
    }
    Some((sta, bssid))
}

fn parse_csv_line(line: &str) -> Option<WifiNetwork> {
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 14 {
        return None;
    }

    let bssid = parts[0].trim().to_string();
    if !bssid.contains(':') || bssid.len() < 17 {
        return None;
    }

    let channel: u8 = parts[3].trim().parse().unwrap_or(0);
    let privacy = parts[5].trim();
    let cipher = parts[6].trim().to_string();
    let auth = parts[7].trim().to_string();
    let power: i32 = parts[8].trim().parse().unwrap_or(-100);
    let essid = parts[13].trim().to_string();

    let security = SecurityType::from_airodump(privacy, &cipher, &auth);
    let vulnerability = Vulnerability::assess(&security, &essid);

    Some(WifiNetwork {
        bssid,
        essid: if essid.is_empty() {
            "<hidden>".to_string()
        } else {
            essid
        },
        channel,
        power,
        security,
        vulnerability,
        cipher,
        auth,
        clients: Vec::new(),
    })
}

fn scan_with_iw(iface: &str) -> Result<Vec<WifiNetwork>> {
    let output = Command::new("iw")
        .args(["dev", iface, "scan", "dump"])
        .output()
        .context("iw scan failed")?;

    if !output.status.success() {
        anyhow::bail!(
            "iw scan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(parse_iw_scan(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_iw_scan(output: &str) -> Vec<WifiNetwork> {
    let bss_re = Regex::new(r"BSS ([0-9a-f:]+)\(").unwrap();
    let mut networks = Vec::new();
    let mut current_bssid = String::new();
    let mut current_essid = String::new();
    let mut current_channel = 0u8;
    let mut current_signal = -100i32;
    let mut has_rsn = false;
    let mut has_wpa = false;
    let mut has_wep = false;
    let mut is_open = true;

    let mut flush = |bssid: &str,
                 essid: &str,
                 channel: u8,
                 signal: i32,
                 has_rsn: bool,
                 has_wpa: bool,
                 has_wep: bool,
                 is_open: bool| {
        if bssid.is_empty() {
            return;
        }
        let security = if has_rsn {
            if has_wpa {
                SecurityType::Wpa2Wpa3
            } else {
                SecurityType::Wpa2Psk
            }
        } else if has_wpa {
            SecurityType::WpaTkip
        } else if has_wep {
            SecurityType::Wep
        } else if is_open {
            SecurityType::Open
        } else {
            SecurityType::Unknown
        };

        let vulnerability = Vulnerability::assess(&security, essid);
        networks.push(WifiNetwork {
            bssid: bssid.to_string(),
            essid: if essid.is_empty() {
                "<hidden>".to_string()
            } else {
                essid.to_string()
            },
            channel,
            power: signal,
            security,
            vulnerability,
            cipher: String::new(),
            auth: String::new(),
            clients: Vec::new(),
        });
    };

    for line in output.lines() {
        if let Some(caps) = bss_re.captures(line) {
            flush(
                &current_bssid,
                &current_essid,
                current_channel,
                current_signal,
                has_rsn,
                has_wpa,
                has_wep,
                is_open,
            );
            current_bssid = caps[1].to_string();
            current_essid.clear();
            current_channel = 0;
            current_signal = -100;
            has_rsn = false;
            has_wpa = false;
            has_wep = false;
            is_open = true;
        } else if line.trim().starts_with("SSID:") {
            current_essid = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("").to_string();
        } else if line.contains("freq:") {
            if let Some(freq) = line.split(':').nth(1).and_then(|f| f.trim().split_whitespace().next()) {
                if let Ok(f) = freq.parse::<u32>() {
                    current_channel = freq_to_channel(f);
                }
            }
        } else if line.contains("signal:") {
            if let Some(sig) = line.split("signal:").nth(1).and_then(|s| s.split_whitespace().next()) {
                current_signal = sig.parse().unwrap_or(-100);
            }
        } else if line.contains("RSN:") {
            has_rsn = true;
            is_open = false;
        } else if line.contains("WPA:") {
            has_wpa = true;
            is_open = false;
        } else if line.contains("Privacy") && line.contains("capability:") {
            has_wep = true;
            is_open = false;
        }
    }

    flush(
        &current_bssid,
        &current_essid,
        current_channel,
        current_signal,
        has_rsn,
        has_wpa,
        has_wep,
        is_open,
    );

    networks
}

fn freq_to_channel(freq: u32) -> u8 {
    match freq {
        2412..=2484 => ((freq - 2412) / 5 + 1) as u8,
        5170..=5825 => ((freq - 5170) / 5 + 34) as u8,
        _ => 0,
    }
}

pub fn print_network_table(networks: &[WifiNetwork]) {
    if networks.is_empty() {
        println!("  {} No WiFi networks detected.", "✗".red());
        return;
    }

    let vuln_count = networks.iter().filter(|n| n.vulnerability.is_vulnerable()).count();

    println!(
        "\n  Found {} network(s), {} vulnerable:\n",
        networks.len().to_string().green(),
        if vuln_count > 0 {
            vuln_count.to_string().red().bold().to_string()
        } else {
            vuln_count.to_string()
        }
    );

    println!(
        "  {:<19} {:<22} {:>3} {:>4} {:>4} {:<12} {}",
        "BSSID", "ESSID", "CH", "PWR", "STA", "SECURITY", "STATUS"
    );
    println!("  {}", "─".repeat(86));

    for net in networks {
        let status = net.vulnerability.label();
        let essid_display = if net.essid.len() > 20 {
            format!("{}…", &net.essid[..19])
        } else {
            net.essid.clone()
        };

        let line = format!(
            "  {:<19} {:<22} {:>3} {:>4} {:>4} {:<12} {}",
            net.bssid,
            essid_display,
            net.channel,
            net.power,
            net.clients.len(),
            net.security.label(),
            status
        );

        if net.vulnerability.is_vulnerable() {
            println!("{}", line.red().bold());
        } else {
            println!("{line}");
        }
    }
}

pub fn vulnerable_networks(networks: &[WifiNetwork]) -> Vec<&WifiNetwork> {
    networks
        .iter()
        .filter(|n| n.vulnerability.is_vulnerable())
        .collect()
}
