use anyhow::{Context, Result, bail};
use colored::Colorize;
use crate::monitor;
use regex::Regex;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

/// Known drivers with reliable packet injection support on Linux.
const INJECTION_DRIVERS: &[&str] = &[
    "ath9k",
    "ath9k_htc",
    "ath5k",
    "rtl8187",
    "r8188eu",
    "rtl8812au",
    "8812au",
    "8188eu",
    "rt2800usb",
    "rt73usb",
    "rt61pci",
    "rt2500usb",
    "carl9170",
    "iwlwifi",
    "rtw88_8822ce",
    "rtw88_8822bu",
    "rtw88_8821ce",
    "rtw88_8821cu",
    "rtw88_8723de",
    "rtw88_8723du",
    "mt76x2u",
    "mt7601u",
    "mt76x0u",
    "zd1211rw",
    "p54usb",
    "p54pci",
    "mac80211_hwsim",
];

#[derive(Debug, Clone)]
pub struct WifiAdapter {
    pub name: String,
    pub phy: String,
    pub mac: String,
    pub driver: String,
    pub is_usb: bool,
    pub monitor_capable: bool,
    pub injection_capable: bool,
    pub current_mode: String,
}

impl WifiAdapter {
    pub fn score(&self) -> u8 {
        let mut score = 0u8;
        if self.monitor_capable {
            score += 4;
        }
        if self.injection_capable {
            score += 2;
        }
        if self.is_usb {
            score += 3;
        }
        if self.current_mode == "monitor" {
            score += 1;
        }
        if self.name.ends_with("mon") {
            score = score.saturating_sub(1);
        }
        score
    }

    /// Rank for attack operations — USB dongles (e.g. wlan1) beat internal cards.
    pub fn attack_score(&self) -> u8 {
        let mut score = self.score();
        if self.is_usb {
            score += 5;
        }
        if self.injection_capable {
            score += 2;
        }
        score
    }

    pub fn is_usable(&self) -> bool {
        self.monitor_capable
    }

    pub fn base_name(&self) -> String {
        monitor::base_interface_name(&self.name)
    }

    pub fn already_monitor(&self) -> bool {
        self.current_mode == "monitor"
    }
}

pub fn detect_adapters() -> Result<Vec<WifiAdapter>> {
    let output = Command::new("iw")
        .args(["dev"])
        .output()
        .context("failed to run `iw dev` — is iw installed?")?;

    if !output.status.success() {
        bail!(
            "iw dev failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let iface_re = Regex::new(r"Interface (\S+)").unwrap();
    let phy_re = Regex::new(r"wiphy (\d+)").unwrap();
    let addr_re = Regex::new(r"addr ([0-9a-f:]{17})").unwrap();
    let type_re = Regex::new(r"type (\S+)").unwrap();

    let mut adapters = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_phy: Option<String> = None;
    let mut current_mac = String::new();
    let mut current_mode = String::from("unknown");

    for line in stdout.lines() {
        if let Some(caps) = iface_re.captures(line) {
            if let Some(name) = current_name.take() {
                adapters.push(build_adapter(
                    name,
                    current_phy.clone().unwrap_or_default(),
                    current_mac.clone(),
                    current_mode.clone(),
                )?);
            }
            current_name = Some(caps[1].to_string());
            current_phy = None;
            current_mac.clear();
            current_mode = String::from("unknown");
        } else if let Some(caps) = phy_re.captures(line) {
            current_phy = Some(format!("phy{}", &caps[1]));
        } else if let Some(caps) = addr_re.captures(line) {
            current_mac = caps[1].to_string();
        } else if let Some(caps) = type_re.captures(line) {
            current_mode = caps[1].to_string();
        }
    }

    if let Some(name) = current_name {
        adapters.push(build_adapter(
            name,
            current_phy.unwrap_or_default(),
            current_mac,
            current_mode,
        )?);
    }

    if adapters.is_empty() {
        adapters.extend(detect_from_sysfs()?);
    }

    Ok(dedupe_by_phy(adapters))
}

/// One entry per PHY — prefer managed base interfaces over leftover mon vifs.
fn dedupe_by_phy(adapters: Vec<WifiAdapter>) -> Vec<WifiAdapter> {
    let mut best: std::collections::HashMap<String, WifiAdapter> = std::collections::HashMap::new();

    for adapter in adapters {
        let phy = adapter.phy.clone();
        if phy.is_empty() {
            best.insert(adapter.name.clone(), adapter);
            continue;
        }
        best.entry(phy)
            .and_modify(|existing| {
                if adapter_pref_rank(&adapter) > adapter_pref_rank(existing) {
                    *existing = adapter.clone();
                }
            })
            .or_insert(adapter);
    }

    let mut result: Vec<_> = best.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn adapter_pref_rank(a: &WifiAdapter) -> u8 {
    let mut rank = a.score();
    if a.current_mode == "managed" {
        rank += 2;
    }
    if !a.name.ends_with("mon") {
        rank += 2;
    }
    rank
}

fn detect_from_sysfs() -> Result<Vec<WifiAdapter>> {
    let net_dir = Path::new("/sys/class/net");
    let mut adapters = Vec::new();

    for entry in fs::read_dir(net_dir).context("cannot read /sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let wireless = entry.path().join("wireless");
        if wireless.exists() {
            adapters.push(build_adapter(
                name,
                String::new(),
                read_mac(&entry.path())?,
                String::from("unknown"),
            )?);
        }
    }

    Ok(adapters)
}

fn read_mac(iface_path: &Path) -> Result<String> {
    let addr = fs::read_to_string(iface_path.join("address"))
        .context("failed to read interface MAC")?;
    Ok(addr.trim().to_string())
}

fn build_adapter(name: String, phy: String, mac: String, current_mode: String) -> Result<WifiAdapter> {
    let phy_name = if phy.is_empty() {
        resolve_phy(&name)?
    } else {
        phy
    };

    let driver = read_driver(&name)?;
    let is_usb = is_usb_adapter(&name);
    let monitor_capable = check_monitor_mode(&phy_name)?;
    let injection_capable = check_injection(&driver, &name, monitor_capable);

    Ok(WifiAdapter {
        name,
        phy: phy_name,
        mac,
        driver,
        is_usb,
        monitor_capable,
        injection_capable,
        current_mode,
    })
}

fn resolve_phy(iface: &str) -> Result<String> {
    let output = Command::new("iw")
        .args(["dev", iface, "info"])
        .output()
        .with_context(|| format!("failed to query interface {iface}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"wiphy (\d+)").unwrap();
    if let Some(caps) = re.captures(&stdout) {
        return Ok(format!("phy{}", &caps[1]));
    }
    Ok(String::new())
}

fn read_driver(iface: &str) -> Result<String> {
    let driver_link = format!("/sys/class/net/{iface}/device/driver");
    let path = fs::read_link(&driver_link);
    match path {
        Ok(p) => Ok(p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()),
        Err(_) => Ok(String::from("unknown")),
    }
}

fn is_usb_adapter(iface: &str) -> bool {
    let device = Path::new("/sys/class/net").join(iface).join("device");
    fs::canonicalize(device)
        .map(|p| p.to_string_lossy().contains("/usb"))
        .unwrap_or(false)
}

fn check_monitor_mode(phy: &str) -> Result<bool> {
    if phy.is_empty() {
        return Ok(false);
    }

    // `iw phy phy0 info` — NOT `iw phy 0 info` (that fails on modern iw)
    let output = Command::new("iw")
        .args(["phy", phy, "info"])
        .output()
        .context("failed to run iw phy info")?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.trim_start().starts_with('*') && line.contains("monitor") {
            return Ok(true);
        }
    }

    Ok(false)
}

fn check_injection(driver: &str, iface: &str, monitor_capable: bool) -> bool {
    if INJECTION_DRIVERS.iter().any(|d| driver.contains(d)) {
        return true;
    }

    if !monitor_capable {
        return false;
    }

    // rtw88 and many modern drivers support injection when in monitor mode
    if driver.starts_with("rtw") || driver.starts_with("mt76") || driver == "iwlwifi" {
        return true;
    }

    // Last resort: ask aireplay-ng if we're root
    if crate::monitor::is_root() {
        return test_injection(iface);
    }

    false
}

fn test_injection(iface: &str) -> bool {
    let output = Command::new("aireplay-ng")
        .args(["--test", iface])
        .output();

    match output {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            combined.contains("Injection is working")
                || combined.contains("30/30: 100%")
                || combined.contains("Seems")
        }
        Err(_) => false,
    }
}

pub fn print_adapter_report(adapters: &[WifiAdapter]) {
    println!("\n{}", "═══ WiFi Adapter Detection ═══".bold().cyan());

    if adapters.is_empty() {
        println!("  {} No wireless adapters detected.", "✗".red());
        return;
    }

    println!(
        "  Found {} wireless adapter(s):\n",
        adapters.len().to_string().green()
    );

    for (i, adapter) in adapters.iter().enumerate() {
        let mon = status_icon(adapter.monitor_capable);
        let inj = status_icon(adapter.injection_capable);
        let highlight = if adapter.monitor_capable && adapter.injection_capable {
            "bold green"
        } else {
            "normal"
        };

        println!(
            "  [{}] {} ({})",
            i + 1,
            adapter.name.color(highlight),
            adapter.mac.dimmed()
        );
        println!("      PHY:     {}", adapter.phy);
        println!("      Driver:  {}", adapter.driver);
        println!(
            "      Bus:     {}",
            if adapter.is_usb {
                "USB (external)".green()
            } else {
                "PCI/internal".normal()
            }
        );
        println!("      Mode:    {}", adapter.current_mode);
        println!(
            "      Monitor: {}  Injection: {}",
            mon, inj
        );
        println!();
    }
}

fn status_icon(ok: bool) -> colored::ColoredString {
    if ok {
        "YES ✓".green().bold()
    } else {
        "NO  ✗".red()
    }
}

pub fn select_adapter<'a>(
    adapters: &'a [WifiAdapter],
    preferred: Option<&str>,
) -> Result<&'a WifiAdapter> {
    if adapters.is_empty() {
        bail!("no wireless adapters found");
    }

    if let Some(name) = preferred {
        let adapter = adapters
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("adapter '{name}' not found"))?;
        print_selection(adapter);
        return Ok(adapter);
    }

    prompt_adapter_choice(adapters)
}

fn prompt_adapter_choice<'a>(adapters: &'a [WifiAdapter]) -> Result<&'a WifiAdapter> {
    println!(
        "\n{}",
        "═══ Select Adapter for Monitor Mode ═══".bold().cyan()
    );

    loop {
        print!(
            "  Select adapter [1-{}], name, or q to quit: ",
            adapters.len()
        );
        io::stdout().flush().context("failed to flush stdout")?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("failed to read selection")?;

        let input = input.trim();
        if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") {
            anyhow::bail!(crate::quit::QuitRequested);
        }

        if input.is_empty() {
            println!("  {} Enter a number or interface name.", "⚠".yellow());
            continue;
        }

        if let Ok(n) = input.parse::<usize>() {
            if (1..=adapters.len()).contains(&n) {
                let adapter = &adapters[n - 1];
                print_selection(adapter);
                return Ok(adapter);
            }
            println!(
                "  {} Invalid number — choose between 1 and {}.",
                "⚠".yellow(),
                adapters.len()
            );
            continue;
        }

        if let Some(adapter) = adapters.iter().find(|a| a.name == input) {
            print_selection(adapter);
            return Ok(adapter);
        }

        println!(
            "  {} Unknown adapter '{}'. Use a number from the list or exact interface name.",
            "⚠".yellow(),
            input
        );
    }
}

fn print_selection(adapter: &WifiAdapter) {
    println!(
        "\n  {} Selected: {} (monitor={}, injection={})",
        "→".cyan(),
        adapter.name.bold(),
        status_icon(adapter.monitor_capable),
        status_icon(adapter.injection_capable)
    );
}