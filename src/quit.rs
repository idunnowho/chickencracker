use anyhow::{Result, bail};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

static QUIT: AtomicBool = AtomicBool::new(false);
static RESTORED: AtomicBool = AtomicBool::new(false);
static LISTENER_STARTED: AtomicBool = AtomicBool::new(false);
static CHILD_PIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static RESTORE_IFACES: Mutex<Option<(String, String)>> = Mutex::new(None);
static ORIG_TERMIOS: Mutex<Option<(i32, libc::termios)>> = Mutex::new(None);

#[derive(Debug)]
pub struct QuitRequested;

impl std::fmt::Display for QuitRequested {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "quit requested")
    }
}

impl std::error::Error for QuitRequested {}

pub fn requested() -> bool {
    QUIT.load(Ordering::SeqCst)
}

pub fn request() {
    QUIT.store(true, Ordering::SeqCst);
    kill_children();
}

pub fn restore_now() {
    restore_tty();
    if RESTORED.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some((original, interface)) = take_restore() {
        crate::monitor::restore_managed_mode(&[crate::monitor::MonitorHandle {
            interface,
            original,
            was_already_monitor: false,
        }]);
    }
}

pub fn abort_if() -> Result<()> {
    if requested() {
        bail!(QuitRequested);
    }
    Ok(())
}

pub fn is_quit(err: &anyhow::Error) -> bool {
    err.downcast_ref::<QuitRequested>().is_some()
        || err.chain().any(|e| e.to_string().contains("quit requested"))
}

pub fn sleep(dur: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < dur {
        abort_if()?;
        let remaining = dur.saturating_sub(start.elapsed());
        thread::sleep(remaining.min(Duration::from_millis(80)));
    }
    abort_if()
}

pub fn track_pid(pid: u32) {
    if let Ok(mut pids) = CHILD_PIDS.lock() {
        pids.push(pid);
    }
}

pub fn untrack_pid(pid: u32) {
    if let Ok(mut pids) = CHILD_PIDS.lock() {
        pids.retain(|p| *p != pid);
    }
}

pub fn kill_children() {
    let pids = CHILD_PIDS.lock().map(|p| p.clone()).unwrap_or_default();
    for pid in pids {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    thread::sleep(Duration::from_millis(80));
    for pid in CHILD_PIDS.lock().map(|p| p.clone()).unwrap_or_default() {
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

pub fn register_restore(original: &str, monitor_iface: &str) {
    if let Ok(mut slot) = RESTORE_IFACES.lock() {
        *slot = Some((original.to_string(), monitor_iface.to_string()));
    }
}

pub fn take_restore() -> Option<(String, String)> {
    RESTORE_IFACES.lock().ok().and_then(|mut s| s.take())
}

pub fn mark_restored() {
    RESTORED.store(true, Ordering::SeqCst);
}

pub fn already_restored() -> bool {
    RESTORED.load(Ordering::SeqCst)
}

pub fn install_handlers() {
    let _ = ctrlc::set_handler(|| {
        request();
        restore_now();
        eprintln!("\n  quit — adapters restored.");
        std::process::exit(0);
    });
}

pub fn start_key_listener() {
    if LISTENER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    thread::spawn(|| {
        let Ok(mut tty) = OpenOptions::new().read(true).open("/dev/tty") else {
            return;
        };
        let fd = tty.as_raw_fd();

        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut term) != 0 {
                return;
            }
            if let Ok(mut orig) = ORIG_TERMIOS.lock() {
                *orig = Some((fd, term));
            }
            term.c_lflag &= !(libc::ICANON | libc::ECHO);
            term.c_cc[libc::VMIN] = 0;
            term.c_cc[libc::VTIME] = 1;
            libc::tcsetattr(fd, libc::TCSANOW, &term);
        }

        let mut buf = [0u8; 8];
        while !requested() {
            match tty.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if buf[..n].iter().any(|b| *b == b'q' || *b == b'Q') {
                        request();
                        restore_now();
                        eprintln!("\n  quit — adapters restored.");
                        std::process::exit(0);
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        restore_tty();
    });
}

pub fn restore_tty() {
    if let Ok(mut orig) = ORIG_TERMIOS.lock() {
        if let Some((fd, term)) = orig.take() {
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, &term);
            }
        }
    }
    print!("\x1b[?25h");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

pub fn hint() -> &'static str {
    "press q to quit"
}
