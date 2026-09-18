use crate::quit;
use colored::Colorize;
use std::io::{self, Write};
use std::time::{Duration, Instant};

const HUD_LINES: u16 = 14;

pub struct CrackHud {
    essid: String,
    bssid: String,
    wordlist: String,
    started: Instant,
    keys: u64,
    total: u64,
    kps: f64,
    current: String,
    frame: usize,
    drawn: bool,
}

impl CrackHud {
    pub fn new(essid: &str, bssid: &str, wordlist: &str) -> Self {
        Self {
            essid: essid.to_string(),
            bssid: bssid.to_string(),
            wordlist: wordlist.to_string(),
            started: Instant::now(),
            keys: 0,
            total: 0,
            kps: 0.0,
            current: String::from("…"),
            frame: 0,
            drawn: false,
        }
    }

    pub fn update(&mut self, keys: u64, total: u64, kps: f64, current: &str) {
        if keys > 0 {
            self.keys = keys;
        }
        if total > 0 {
            self.total = total;
        }
        if kps > 0.0 {
            self.kps = kps;
        }
        if !current.is_empty() {
            self.current = current.to_string();
        }
        self.frame = self.frame.wrapping_add(1);
        self.draw();
    }

    pub fn tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        if self.kps <= 0.0 && self.keys > 0 {
            self.kps = self.keys as f64 / elapsed / 1000.0;
        }
        self.draw();
    }

    pub fn finish_found(&mut self, password: &str) {
        self.current = password.to_string();
        self.draw();
        println!();
        println!(
            "           {}  [ {} ]",
            "KEY FOUND".green().bold(),
            password.green().bold()
        );
        println!();
    }

    pub fn finish_miss(&mut self) {
        self.draw();
        println!();
        println!("           {}", "not in wordlist".red());
        println!();
    }

    fn draw(&mut self) {
        let mut out = io::stdout();
        if self.drawn {
            let _ = write!(out, "\x1b[{HUD_LINES}A");
        } else {
            let _ = write!(out, "\x1b[?25l");
        }

        let elapsed = self.started.elapsed();
        let pct = if self.total > 0 {
            (self.keys as f64 / self.total as f64 * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        let bar = progress_bar(pct, 42);
        let bird = chicken_frame(self.frame);
        let wave = wave_frame(self.frame);
        let wl = truncate(&self.wordlist, 46);
        let trying = truncate(&self.current, 32);
        let total_s = if self.total > 0 {
            format!("{}", commas(self.total))
        } else {
            "?".into()
        };

        let lines = [
            format!("  ╔══════════════════════════════════════════════════════════╗"),
            format!(
                "  ║  {} {:>27} ║",
                "CHICKENCRACKER".yellow().bold(),
                bird
            ),
            format!("  ╠══════════════════════════════════════════════════════════╣"),
            format!(
                "  ║  essid    {:<47} ║",
                truncate(&self.essid, 47)
            ),
            format!("  ║  bssid    {:<47} ║", truncate(&self.bssid, 47)),
            format!("  ║  list     {:<47} ║", wl),
            format!("  ╠══════════════════════════════════════════════════════════╣"),
            format!("  ║  {bar} {pct:>5.1}%  ║"),
            format!(
                "  ║  tested   {:<14}  speed  {:>10} k/s         ║",
                commas(self.keys),
                format!("{:.2}", self.kps)
            ),
            format!(
                "  ║  elapsed  {:<14}  keys   {:>14}        ║",
                fmt_dur(elapsed),
                total_s
            ),
            format!("  ║  trying   {:<47} ║", trying),
            format!("  ║  {wave:<56} ║"),
            format!(
                "  ║  {}{:>43} ║",
                quit::hint().dimmed(),
                ""
            ),
            format!("  ╚══════════════════════════════════════════════════════════╝"),
        ];

        for line in &lines {
            let _ = writeln!(out, "{line}");
        }
        let _ = out.flush();
        self.drawn = true;
    }
}

impl Drop for CrackHud {
    fn drop(&mut self) {
        print!("\x1b[?25h");
        let _ = io::stdout().flush();
    }
}

fn progress_bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let blocks = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];
    let mut s = String::from("[");
    for i in 0..width {
        if i < filled {
            s.push('█');
        } else if i == filled {
            s.push_str(blocks[(pct as usize / 3) % blocks.len()]);
        } else {
            s.push('░');
        }
    }
    s.push(']');
    s
}

fn chicken_frame(frame: usize) -> String {
    const FRAMES: [&str; 4] = [
        r#"\\ (o>  peck"#,
        r#"   (O>  peck"#,
        r#"// (o>  peck"#,
        r#"   (O>  crack"#,
    ];
    FRAMES[frame / 2 % FRAMES.len()].to_string()
}

fn wave_frame(frame: usize) -> String {
    const WAVE: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    (0..54)
        .map(|i| WAVE[(i + frame) % WAVE.len()])
        .collect()
}

fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}
