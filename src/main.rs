mod adapter;
mod anim;
mod crack;
mod handshake;
mod monitor;
mod quit;
mod scanner;
mod security;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;
use std::process::exit;

#[derive(Parser, Debug)]
#[command(
    name = "chickencracker",
    about = "WiFi security assessment tool — adapter detection, scanning, handshake capture, and cracking",
    version
)]
struct Args {
    /// Wireless interface (skips interactive adapter selection)
    #[arg(short, long)]
    interface: Option<String>,

    /// Scan duration in seconds
    #[arg(long, default_value = "15")]
    scan_time: u64,

    /// Handshake capture timeout per network in seconds
    #[arg(long, default_value = "30")]
    capture_time: u64,

    /// Wordlist path for dictionary attack
    #[arg(short, long)]
    wordlist: Option<PathBuf>,

    /// Output directory for captures and scan data
    #[arg(short, long, default_value = "./output")]
    output: PathBuf,

    /// Skip handshake capture (scan only)
    #[arg(long)]
    scan_only: bool,

    /// Skip cracking (capture only)
    #[arg(long)]
    capture_only: bool,

    /// Use aircrack-ng for cracking (default; faster for handshakes)
    #[arg(long, default_value_t = true)]
    aircrack: bool,
}

fn main() {
    if let Err(e) = run() {
        quit::restore_tty();
        if quit::is_quit(&e) {
            println!("\n  {} Quit — adapters restored.", "✓".green());
            exit(0);
        }
        eprintln!("\n{} {e:#}", "ERROR:".red().bold());
        exit(1);
    }
}

fn run() -> Result<()> {
    print_banner();

    let args = Args::parse();
    quit::install_handlers();

    // ── Step 1: Detect adapters ──────────────────────────────────────
    let adapters = adapter::detect_adapters()?;
    adapter::print_adapter_report(&adapters);

    if adapters.is_empty() {
        anyhow::bail!("no wireless adapters detected — plug in a compatible USB WiFi adapter");
    }

    // ── Step 2: Choose adapter ───────────────────────────────────────
    let selected = adapter::select_adapter(&adapters, args.interface.as_deref())?;

    if !selected.monitor_capable {
        println!(
            "\n  {} {} does not support monitor mode — handshake capture will not work.",
            "⚠".yellow().bold(),
            selected.name
        );
    }

    if !selected.injection_capable {
        println!(
            "  {} {} may not support packet injection — deauth attacks might fail.",
            "⚠".yellow(),
            selected.name
        );
    }

    // ── Step 3: Require root and enable monitor mode ─────────────────
    monitor::require_root()?;

    let setup_iface = if selected.already_monitor() {
        selected.name.clone()
    } else {
        selected.base_name()
    };

    quit::register_restore(&setup_iface, &format!("{setup_iface}mon"));
    quit::start_key_listener();
    let mon_handle = monitor::enable_monitor_mode(&setup_iface)?;
    quit::register_restore(&mon_handle.original, &mon_handle.interface);
    let iface = mon_handle.interface.clone();

    let result = (|| -> Result<()> {
        let scan_dir = args.output.join("scan");
        let capture_dir = args.output.join("captures");

        // ── Step 4: Scan for networks ──────────────────────────────
        let networks = scanner::scan_networks(&iface, args.scan_time, &scan_dir)?;

        scanner::print_network_table(&networks);

        if networks.is_empty() {
            return Ok(());
        }

        let vuln: Vec<_> = scanner::vulnerable_networks(&networks);

        if vuln.is_empty() {
            println!(
                "\n  {} No vulnerable networks found — all targets appear secure.",
                "✓".green()
            );
            return Ok(());
        }

        println!(
            "\n  {} {} vulnerable network(s) identified for attack.",
            "⚠".yellow().bold(),
            vuln.len()
        );

        if args.scan_only {
            println!("\n  {} Scan-only mode — skipping capture and crack.", "ℹ".blue());
            return Ok(());
        }

        // ── Step 5: Handshake capture ────────────────────────────────
        handshake::handle_non_wpa_targets(&vuln);

        let captures = handshake::capture_handshakes(
            &iface,
            &vuln,
            &capture_dir,
            args.capture_time,
        )?;

        if args.capture_only {
            println!("\n  {} Capture-only mode — skipping crack.", "ℹ".blue());
            return Ok(());
        }

        // ── Step 6: Brute-force / dictionary attack ──────────────────
        let wordlist = args.wordlist.unwrap_or_else(crack::default_wordlist);

        if !wordlist.exists() {
            println!(
                "\n  {} Wordlist not found at {}. Skipping crack.",
                "⚠".yellow(),
                wordlist.display()
            );
            println!("  Specify one with: --wordlist /path/to/wordlist.txt");
            return Ok(());
        }

        let results = crack::crack_captures(&captures, &wordlist, args.aircrack)?;
        crack::print_crack_summary(&results);

        Ok(())
    })();

    if !quit::already_restored() {
        monitor::restore_managed_mode(std::slice::from_ref(&mon_handle));
        quit::mark_restored();
    }
    quit::restore_tty();

    if let Err(e) = &result {
        if quit::is_quit(e) {
            println!("\n  {} Quit — adapters restored.", "✓".green());
            return Ok(());
        }
    }

    result
}

fn print_banner() {
    println!(
        r#"
  {}
  {}
  {}"#,
        "╔═══════════════════════════════════════╗".cyan(),
        "║   CHICKENCRACKER — WiFi Security Tool ║".cyan().bold(),
        "╚═══════════════════════════════════════╝".cyan()
    );
    println!(
        "  {} Authorized security testing only.  {}",
        "⚠".yellow(),
        "press q to quit".dimmed()
    );
}
