use crate::anim::CrackHud;
use crate::handshake::HandshakeCapture;
use crate::quit;
use anyhow::{Context, Result, bail};
use colored::Colorize;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rayon::prelude::*;
use regex::Regex;
use sha1::Sha1;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct CrackResult {
    pub essid: String,
    pub bssid: String,
    pub password: Option<String>,
    pub method: String,
}

pub fn crack_captures(
    captures: &[HandshakeCapture],
    wordlist: &Path,
    use_aircrack: bool,
) -> Result<Vec<CrackResult>> {
    let crackable: Vec<_> = captures.iter().filter(|c| c.captured).collect();

    if crackable.is_empty() {
        println!(
            "\n  {} No handshakes to crack.",
            "ℹ".blue()
        );
        return Ok(Vec::new());
    }

    if !wordlist.exists() {
        bail!(
            "wordlist not found: {}. Try: /usr/share/wordlists/rockyou.txt",
            wordlist.display()
        );
    }

    println!(
        "\n{}",
        "═══ Brute-Force / Dictionary Attack ═══".bold().cyan()
    );
    println!("  Wordlist: {}", wordlist.display());
    println!("  {}\n", quit::hint().dimmed());

    let mut results = Vec::new();

    for capture in crackable {
        println!(
            "  Cracking {} ({})...",
            capture.network.essid.bold(),
            capture.network.bssid.dimmed()
        );

        let result = if use_aircrack {
            crack_with_aircrack(capture, wordlist)?
        } else {
            crack_with_rust(capture, wordlist).or_else(|_| crack_with_aircrack(capture, wordlist))?
        };

        match &result.password {
            Some(_) => {}
            None => {
                if quit::requested() {
                    quit::abort_if()?;
                }
            }
        }

        results.push(result);
    }

    Ok(results)
}

fn crack_with_aircrack(capture: &HandshakeCapture, wordlist: &Path) -> Result<CrackResult> {
    let child = Command::new("stdbuf")
        .args([
            "-oL",
            "-eL",
            "aircrack-ng",
            "-w",
            &wordlist.to_string_lossy(),
            "-b",
            &capture.network.bssid,
            "-a",
            "2",
            &capture.cap_file.to_string_lossy(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(_) => Command::new("aircrack-ng")
            .args([
                "-w",
                &wordlist.to_string_lossy(),
                "-b",
                &capture.network.bssid,
                "-a",
                "2",
                &capture.cap_file.to_string_lossy(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("aircrack-ng failed to start")?,
    };

    let pid = child.id();
    quit::track_pid(pid);

    if let Some(out) = child.stdout.as_ref() {
        set_nonblock(out);
    }
    if let Some(err) = child.stderr.as_ref() {
        set_nonblock(err);
    }

    let mut hud = CrackHud::new(
        &capture.network.essid,
        &capture.network.bssid,
        &wordlist.display().to_string(),
    );

    let keys_re =
        Regex::new(r"\[(\d+:\d+:\d+)\]\s+([\d,]+)(?:/([\d,]+))?\s+keys tested\s+\(([\d.]+)\s*k/s\)")
            .unwrap();
    let pass_re = Regex::new(r"(?i)(?:current passphrase|Trying)\s*[:\[]\s*([^\]]+?)\s*\]?\s*$").unwrap();

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut combined = String::new();
    let mut buf = [0u8; 2048];
    let mut leftover = String::new();

    loop {
        if quit::requested() {
            let _ = child.kill();
            break;
        }

        let mut got = false;
        if let Some(s) = stdout.as_mut() {
            match s.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    got = true;
                    leftover.push_str(&String::from_utf8_lossy(&buf[..n]));
                    leftover = leftover.replace('\r', "\n");
                    combined.push_str(&String::from_utf8_lossy(&buf[..n]));
                    combined.push('\n');
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
        if let Some(s) = stderr.as_mut() {
            match s.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    got = true;
                    leftover.push_str(&String::from_utf8_lossy(&buf[..n]));
                    leftover = leftover.replace('\r', "\n");
                    combined.push_str(&String::from_utf8_lossy(&buf[..n]));
                    combined.push('\n');
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }

        while let Some(idx) = leftover.find('\n') {
            let line = leftover[..idx].to_string();
            leftover.drain(..=idx);
            if let Some(caps) = keys_re.captures(&line) {
                let keys = caps[2].replace(',', "").parse().unwrap_or(0);
                let total = caps
                    .get(3)
                    .and_then(|m| m.as_str().replace(',', "").parse().ok())
                    .unwrap_or(0);
                let kps = caps[4].parse().unwrap_or(0.0);
                hud.update(keys, total, kps, "");
            }
            if let Some(caps) = pass_re.captures(&line) {
                hud.update(0, 0, 0.0, caps[1].trim());
            }
        }

        if !got {
            hud.tick();
            if let Err(e) = quit::sleep(Duration::from_millis(80)) {
                let _ = child.kill();
                let _ = child.wait();
                quit::untrack_pid(pid);
                return Err(e);
            }
        }

        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => break,
        }
    }

    let _ = child.wait();
    quit::untrack_pid(pid);
    quit::abort_if()?;

    // Drain remaining
    combined.push_str(&leftover);
    let password = extract_aircrack_password(&combined);

    if let Some(ref pw) = password {
        hud.finish_found(pw);
    } else {
        hud.finish_miss();
    }

    Ok(CrackResult {
        essid: capture.network.essid.clone(),
        bssid: capture.network.bssid.clone(),
        password,
        method: "aircrack-ng".into(),
    })
}

fn set_nonblock<T: std::os::fd::AsRawFd>(s: &T) {
    let fd = s.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn extract_aircrack_password(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("KEY FOUND") {
            if let Some((_, rest)) = line.split_once('[') {
                if let Some(pw) = rest.strip_suffix(']') {
                    return Some(pw.trim().to_string());
                }
            }
            if let Some(pw) = line.split(':').nth(1) {
                return Some(pw.trim().to_string());
            }
        }
    }
    None
}

fn crack_with_rust(capture: &HandshakeCapture, wordlist: &Path) -> Result<CrackResult> {
    let mut eapol = parse_eapol_from_cap(&capture.cap_file, &capture.network.bssid)?;
    eapol.ssid = capture.network.essid.clone();

    let passwords: Vec<String> = BufReader::new(File::open(wordlist)?)
        .lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && l.len() >= 8 && l.len() <= 63)
        .collect();

    let found = Arc::new(AtomicBool::new(false));
    let tested = Arc::new(AtomicU64::new(0));
    let current = Arc::new(Mutex::new(String::from("…")));
    let result_pw = Arc::new(Mutex::new(None::<String>));
    let total = passwords.len() as u64;

    let run = Arc::new(AtomicBool::new(true));
    let hud_found = found.clone();
    let hud_tested = tested.clone();
    let hud_current = current.clone();
    let hud_run = run.clone();
    let essid = capture.network.essid.clone();
    let bssid = capture.network.bssid.clone();
    let wl = wordlist.display().to_string();

    let hud_thread = thread::spawn(move || {
        let mut hud = CrackHud::new(&essid, &bssid, &wl);
        while hud_run.load(Ordering::Relaxed) && !quit::requested() {
            let cur = hud_current.lock().map(|g| g.clone()).unwrap_or_default();
            let keys = hud_tested.load(Ordering::Relaxed);
            hud.update(keys, total, 0.0, &cur);
            if hud_found.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(80));
        }
        hud
    });

    passwords.par_iter().for_each(|password| {
        if found.load(Ordering::Relaxed) || quit::requested() {
            return;
        }
        tested.fetch_add(1, Ordering::Relaxed);
        if tested.load(Ordering::Relaxed) % 64 == 0 {
            if let Ok(mut g) = current.lock() {
                *g = password.clone();
            }
        }
        if verify_wpa_password(password, &eapol) {
            found.store(true, Ordering::Relaxed);
            if let Ok(mut guard) = result_pw.lock() {
                *guard = Some(password.clone());
            }
            if let Ok(mut g) = current.lock() {
                *g = password.clone();
            }
        }
    });

    run.store(false, Ordering::Relaxed);
    let password = result_pw.lock().ok().and_then(|g| g.clone());
    if let Ok(mut hud) = hud_thread.join() {
        if let Some(ref pw) = password {
            hud.finish_found(pw);
        } else {
            hud.finish_miss();
        }
    }

    quit::abort_if()?;

    Ok(CrackResult {
        essid: capture.network.essid.clone(),
        bssid: capture.network.bssid.clone(),
        password,
        method: "rust-pbkdf2".into(),
    })
}

#[derive(Debug, Clone)]
struct EapolData {
    ssid: String,
    ap_mac: [u8; 6],
    client_mac: [u8; 6],
    anonce: [u8; 32],
    snonce: [u8; 32],
    eapol_frame: Vec<u8>,
    mic: [u8; 16],
    key_version: u8,
}

fn parse_eapol_from_cap(cap_path: &Path, bssid: &str) -> Result<EapolData> {
    // Use aircrack-ng to export hash if native parsing fails
    let _output = Command::new("aircrack-ng")
        .args(["-J", "/tmp/chickencracker_hash", &cap_path.to_string_lossy()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let data = fs::read(cap_path).context("failed to read cap file")?;
    parse_pcap_eapol(&data, bssid)
}

fn parse_pcap_eapol(data: &[u8], target_bssid: &str) -> Result<EapolData> {
    if data.len() < 24 {
        bail!("cap file too small");
    }

    let mut offset = 24; // skip pcap global header
    let mut eapol_data: Option<EapolData> = None;
    let target = parse_mac(target_bssid)?;

    while offset + 16 <= data.len() {
        let incl_len = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;
        offset += 16;

        if offset + incl_len > data.len() {
            break;
        }

        let frame = &data[offset..offset + incl_len];
        offset += incl_len;

        if let Some(eapol) = extract_eapol(frame, &target) {
            eapol_data = Some(eapol);
        }
    }

    eapol_data.context("no EAPOL handshake found in capture")
}

fn extract_eapol(frame: &[u8], target_bssid: &[u8; 6]) -> Option<EapolData> {
    if frame.len() < 36 {
        return None;
    }

    // Skip radiotap header (variable length)
    let mut i = 0usize;
    if frame.len() >= 2 {
        let radiotap_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        if radiotap_len > 0 && radiotap_len < frame.len() {
            i = radiotap_len;
        }
    }

    if i + 34 > frame.len() {
        return None;
    }

    // 802.11 data frame: check type/subtype for data (0x08) or QoS data (0x88)
    let fc = u16::from_le_bytes([frame[i], frame[i + 1]]);
    let frame_type = (fc >> 2) & 0x3;
    let frame_subtype = (fc >> 4) & 0xF;

    if frame_type != 2 {
        return None;
    }

    let to_ds = (fc >> 8) & 1;
    let from_ds = (fc >> 9) & 1;

    let (_addr1, addr2, addr3) = if to_ds == 1 && from_ds == 0 {
        (
            &frame[i + 4..i + 10],
            &frame[i + 10..i + 16],
            &frame[i + 16..i + 22],
        )
    } else if to_ds == 0 && from_ds == 1 {
        (
            &frame[i + 4..i + 10],
            &frame[i + 16..i + 22],
            &frame[i + 10..i + 16],
        )
    } else {
        return None;
    };

    let mut hdr_offset = i + 24;
    let qos = frame_subtype == 0x08;
    if qos {
        hdr_offset += 2;
    }

    // LLC/SNAP header
    if hdr_offset + 8 > frame.len() {
        return None;
    }

    let llc = &frame[hdr_offset..hdr_offset + 8];
    if llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 {
        return None;
    }

    let ethertype = u16::from_be_bytes([llc[6], llc[7]]);
    if ethertype != 0x888E {
        return None;
    }

    let eapol_start = hdr_offset + 8;
    if eapol_start + 99 > frame.len() {
        return None;
    }

    let eapol = &frame[eapol_start..];
    if eapol[0] != 0x01 || eapol[1] != 0x03 {
        return None;
    }

    let key_info = u16::from_be_bytes([eapol[5], eapol[6]]);
    let key_version = (key_info & 0x7) as u8;
    let has_mic = key_info & 0x100 != 0;

    if !has_mic {
        return None;
    }

    let mic: [u8; 16] = eapol[77..93].try_into().ok()?;
    let anonce: [u8; 32] = eapol[17..49].try_into().ok()?;
    let snonce: [u8; 32] = eapol[49..81].try_into().ok()?;

    let ap_mac: [u8; 6] = addr3.try_into().ok()?;
    let client_mac: [u8; 6] = addr2.try_into().ok()?;

    if &ap_mac != target_bssid {
        return None;
    }

    Some(EapolData {
        ssid: String::new(),
        ap_mac,
        client_mac,
        anonce,
        snonce,
        eapol_frame: eapol.to_vec(),
        mic,
        key_version,
    })
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<u8> = s
        .split(':')
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<_, _>>()
        .context("invalid MAC address")?;
    if parts.len() != 6 {
        bail!("invalid MAC length");
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

fn verify_wpa_password(password: &str, eapol: &EapolData) -> bool {
    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha1>(password.as_bytes(), eapol.ssid.as_bytes(), 4096, &mut pmk);

    let ptk = compute_ptk(
        &pmk,
        &eapol.ap_mac,
        &eapol.client_mac,
        &eapol.anonce,
        &eapol.snonce,
    );

    let kck = &ptk[0..16];
    let computed_mic = compute_mic(kck, &eapol.eapol_frame, eapol.key_version);

    computed_mic == eapol.mic
}

fn compute_ptk(
    pmk: &[u8; 32],
    ap_mac: &[u8; 6],
    client_mac: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 64] {
    let mut data = Vec::with_capacity(76);
    data.extend_from_slice(b"Pairwise key expansion");

    let (mac_min, mac_max) = if ap_mac <= client_mac {
        (ap_mac, client_mac)
    } else {
        (client_mac, ap_mac)
    };
    let (nonce_min, nonce_max) = if anonce <= snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };

    data.push(0);
    data.extend_from_slice(mac_min);
    data.extend_from_slice(mac_max);
    data.extend_from_slice(nonce_min);
    data.extend_from_slice(nonce_max);
    data.push(0);

    prf512(pmk, &data)
}

fn prf512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];
    for i in 0..4 {
        let mut input = data.to_vec();
        input.push(i as u8);
        let block = hmac_sha1(key, &input);
        result[i * 20..(i + 1) * 20].copy_from_slice(&block[..20.min(64 - i * 20)]);
    }
    result
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

fn compute_mic(kck: &[u8], eapol: &[u8], key_version: u8) -> [u8; 16] {
    let mut frame = eapol.to_vec();
    if frame.len() >= 93 {
        frame[77..93].fill(0);
    }

    let mut mac = HmacSha1::new_from_slice(kck).expect("HMAC key");
    mac.update(&frame);
    let result = mac.finalize().into_bytes();

    let mut mic = [0u8; 16];
    if key_version == 1 {
        mic.copy_from_slice(&result[..16]);
    } else {
        mic.copy_from_slice(&result[..16]);
    }
    mic
}

pub fn default_wordlist() -> PathBuf {
    const CANDIDATES: &[&str] = &[
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/john/password.lst",
    ];

    for path in CANDIDATES {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    PathBuf::from("/usr/share/wordlists/rockyou.txt")
}

pub fn print_crack_summary(results: &[CrackResult]) {
    println!(
        "\n{}",
        "═══ Crack Results Summary ═══".bold().cyan()
    );

    let cracked: Vec<_> = results.iter().filter(|r| r.password.is_some()).collect();

    if cracked.is_empty() {
        println!("  {} No passwords recovered.", "✗".red());
        return;
    }

    for r in cracked {
        println!(
            "  {} {} → {}",
            "★".green(),
            r.essid.bold(),
            r.password.as_ref().unwrap().green().bold()
        );
    }
}
