# chickencracker

Linux WiFi security assessment tool written in Rust. It detects wireless adapters, scans nearby networks, captures WPA/WPA2 handshakes, and runs dictionary attacks against captured handshakes.

**Authorized testing only.** Use this only on networks you own or have explicit written permission to assess.

## Features

- USB/wireless adapter detection with monitor-mode and injection capability scoring
- Interactive adapter selection (or pass `-i` / `--interface`)
- Network scanning via `airodump-ng`
- Handshake capture with timed capture windows
- Dictionary cracking via `aircrack-ng` (default) or a built-in Rust fallback
- Clean shutdown: press `q` to quit and restore managed mode on adapters

## Requirements

| Requirement | Notes |
|-------------|--------|
| Linux | Designed for Linux wireless tooling (`iw`, `ip`, aircrack-ng suite) |
| Root | Monitor mode and capture need `sudo` |
| Compatible WiFi adapter | Prefer chipsets that support monitor mode + packet injection |
| [Rust toolchain](https://rustup.rs/) | To build from source |
| [aircrack-ng](https://www.aircrack-ng.org/) | Provides `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng` |
| Wordlist | Optional; defaults search common paths such as `/usr/share/wordlists/rockyou.txt` |

### Install system dependencies (Debian/Ubuntu/Kali-style)

```bash
sudo apt update
sudo apt install -y aircrack-ng iw wireless-tools build-essential pkg-config
# Optional wordlist (large):
# sudo apt install -y wordlists
```

## Build

```bash
cargo build --release
```

Binary: `./target/release/chickencracker`

## Quick start

1. Plug in a compatible external WiFi adapter.
2. Build the release binary (see above).
3. Run as root:

```bash
sudo ./target/release/chickencracker
```

The app will:

1. Detect and score adapters
2. Ask you to pick one (unless `-i` is set)
3. Enable monitor mode
4. Scan for networks
5. Capture handshakes on vulnerable targets
6. Attempt dictionary cracking if a wordlist is available

Press **`q`** at any time to quit and restore adapters to managed mode.

## CLI options

```text
chickencracker [OPTIONS]

Options:
  -i, --interface <INTERFACE>      Wireless interface (skips interactive selection)
      --scan-time <SECONDS>        Scan duration [default: 15]
      --capture-time <SECONDS>     Handshake capture timeout per network [default: 30]
  -w, --wordlist <PATH>            Wordlist for dictionary attack
  -o, --output <DIR>               Output directory [default: ./output]
      --scan-only                  Scan only (no capture/crack)
      --capture-only               Capture only (no crack)
      --aircrack                   Use aircrack-ng for cracking [default: true]
  -h, --help                       Print help
  -V, --version                    Print version
```

### Examples

```bash
# Full interactive run
sudo ./target/release/chickencracker

# Pick interface and custom wordlist
sudo ./target/release/chickencracker -i wlan1 -w /path/to/wordlist.txt

# Longer scan, capture only (no cracking)
sudo ./target/release/chickencracker --scan-time 30 --capture-only

# Recon only
sudo ./target/release/chickencracker --scan-only -o ./recon
```

## Output layout

By default files are written under `./output`:

```text
output/
  scan/        # airodump scan CSVs / related scan data
  captures/    # handshake capture files
```

## Troubleshooting

| Problem | What to check |
|---------|----------------|
| No adapters detected | Adapter plugged in? Drivers loaded? `ip link` / `iw dev` |
| Monitor mode fails | Run as root; try `airmon-ng check kill` conflicts (NetworkManager, wpa_supplicant) |
| Scan empty | Adapter in monitor mode? RF kill off? (`rfkill unblock wifi`) |
| No handshake | Clients associated? Injection support? Increase `--capture-time` |
| Crack skipped | Wordlist missing — pass `-w` or install rockyou / another list |
| Stuck interface after Ctrl+C | Prefer `q` for clean restore; otherwise `airmon-ng stop <iface>mon` and bring the base iface back up |

## Project layout

```text
src/
  main.rs        CLI entrypoint and pipeline
  adapter.rs     Adapter detection / selection
  monitor.rs     Monitor mode setup and restore
  scanner.rs     Network scanning
  handshake.rs   Handshake capture
  crack.rs       Dictionary cracking
  security.rs    Security classification helpers
  anim.rs        Progress / HUD
  quit.rs        Quit handlers and TTY restore
```

## License / disclaimer

This project is for educational and authorized security testing. Unauthorized access to computer networks is illegal. You are responsible for complying with local laws and obtaining permission before use.
