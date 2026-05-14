//! Tiny stderr progress indicator for `installguard scan` / `ci` /
//! `lock` / `attest`. A single line is redrawn in place at ~10 Hz with
//! a Braille spinner and a `done/total` counter; on `finish()` the line
//! is cleared so the regular pretty output starts on column 0.
//!
//! No external dependencies — this is intentionally a 90-line helper
//! rather than a pull of `indicatif` for one cosmetic feature. We tick
//! from a Tokio task so the spinner keeps moving even when the network
//! stalls and no completions are landing.
//!
//! The indicator is fully disabled when:
//!   * stderr is not a TTY (CI, redirected, piped)
//!   * `NO_COLOR` is set (https://no-color.org — we treat it as
//!     "no decorative output", consistent with the rest of the CLI)
//!
//! In disabled mode every method is a cheap no-op so callers can
//! always construct a `Progress`.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Braille spinner frames — same set used by `indicatif`'s default
/// `dots` style. Width=1 column on every frame so the redraw is stable.
const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Shared mutable state between the public handle and the ticker task.
struct Inner {
    done: AtomicUsize,
    total: usize,
    label: &'static str,
}

pub struct Progress {
    inner: Arc<Inner>,
    ticker: Option<JoinHandle<()>>,
}

impl Progress {
    /// Build a new progress indicator and spawn the background ticker.
    /// Returns a no-op handle when stderr cannot render the spinner.
    #[must_use]
    pub fn start(total: usize, label: &'static str) -> Self {
        if total == 0 || !should_render() {
            return Self {
                inner: Arc::new(Inner {
                    done: AtomicUsize::new(0),
                    total,
                    label,
                }),
                ticker: None,
            };
        }
        let inner = Arc::new(Inner {
            done: AtomicUsize::new(0),
            total,
            label,
        });
        let weak = Arc::clone(&inner);
        let ticker = tokio::spawn(async move {
            let mut frame: usize = 0;
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            // Skip the first immediate tick; the first redraw happens
            // after one interval rather than racing the caller's setup.
            interval.tick().await;
            loop {
                interval.tick().await;
                redraw(&weak, FRAMES[frame % FRAMES.len()]);
                frame = frame.wrapping_add(1);
            }
        });
        Self {
            inner,
            ticker: Some(ticker),
        }
    }

    /// Record one completed unit of work. Cheap atomic increment;
    /// the next ticker frame picks it up.
    pub fn inc(&self) {
        self.inner.done.fetch_add(1, Ordering::Relaxed);
    }

    /// Stop the ticker and clear the line so subsequent output starts
    /// on column 0. Idempotent.
    pub fn finish(mut self) {
        if let Some(t) = self.ticker.take() {
            t.abort();
            // Clear the in-place line. `\r` returns to column 0,
            // `\x1b[2K` erases the whole line.
            let mut err = std::io::stderr().lock();
            let _ = err.write_all(b"\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(t) = self.ticker.take() {
            t.abort();
            let mut err = std::io::stderr().lock();
            let _ = err.write_all(b"\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

fn should_render() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stderr().is_terminal()
}

fn redraw(inner: &Inner, frame: &str) {
    let done = inner.done.load(Ordering::Relaxed);
    let total = inner.total;
    let mut err = std::io::stderr().lock();
    // \r → col 0, \x1b[2K → erase line, then the status. No newline.
    let _ = write!(err, "\r\x1b[2K  {frame} {} {done}/{total}", inner.label);
    let _ = err.flush();
}
