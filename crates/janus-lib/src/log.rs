//! The daemon's log: every line goes to stderr as before and into an in-memory ring, from which
//! `janus-cli client logs` reads it (the last N lines, and new ones live with `-f`).
//!
//! Use the `jlog!` macro: `jlog!(Info, "smb", "conn {id} established")`. The component is a
//! short static tag (`smb`, `daemon`, `backend`, `control`) that clients can filter on.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use tokio::sync::broadcast;

/// Lines kept for `logs` (oldest are dropped).
pub const RING_LINES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }

    pub fn from_u32(v: u32) -> Level {
        match v {
            0 => Level::Debug,
            2 => Level::Warn,
            3 => Level::Error,
            _ => Level::Info,
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Line {
    pub seq: u64,
    pub unix_ms: i64,
    pub level: Level,
    pub component: &'static str,
    pub text: String,
}

/// What a reader wants to see.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub min_level: Option<Level>,
    /// Empty = all components.
    pub components: Vec<String>,
    /// Case-insensitive substring of the text; empty = anything.
    pub contains: String,
}

impl Filter {
    pub fn matches(&self, l: &Line) -> bool {
        self.min_level.is_none_or(|m| l.level >= m)
            && (self.components.is_empty() || self.components.iter().any(|c| c == l.component))
            && (self.contains.is_empty()
                || l.text
                    .to_lowercase()
                    .contains(&self.contains.to_lowercase()))
    }
}

struct Hub {
    ring: Mutex<(VecDeque<Line>, u64)>,
    tx: broadcast::Sender<Line>,
}

fn hub() -> &'static Hub {
    static HUB: OnceLock<Hub> = OnceLock::new();
    HUB.get_or_init(|| Hub {
        ring: Mutex::new((VecDeque::new(), 0)),
        tx: broadcast::channel(4096).0,
    })
}

/// Record a line (and print it to stderr). Use `jlog!` instead of calling this directly.
pub fn emit(level: Level, component: &'static str, text: String) {
    let h = hub();
    eprintln!("{} {component}: {text}", level.name());
    let unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let mut ring = h.ring.lock().expect("log ring poisoned");
    ring.1 += 1;
    let line = Line {
        seq: ring.1,
        unix_ms,
        level,
        component,
        text,
    };
    if ring.0.len() >= RING_LINES {
        ring.0.pop_front();
    }
    ring.0.push_back(line.clone());
    // Sent under the lock so that `subscribe` never misses or repeats a line.
    let _ = h.tx.send(line);
}

/// The last `tail` matching lines, and a receiver of everything logged from now on.
pub fn subscribe(tail: usize, filter: &Filter) -> (Vec<Line>, broadcast::Receiver<Line>) {
    let h = hub();
    let ring = h.ring.lock().expect("log ring poisoned");
    let rx = h.tx.subscribe();
    let mut lines: Vec<Line> = ring
        .0
        .iter()
        .rev()
        .filter(|l| filter.matches(l))
        .take(tail)
        .cloned()
        .collect();
    lines.reverse();
    (lines, rx)
}

#[macro_export]
macro_rules! jlog {
    ($level:ident, $component:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::Level::$level, $component, format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_filter_and_live_follow() {
        emit(Level::Info, "t-a", "first line".into());
        emit(Level::Debug, "t-b", "noise".into());
        emit(Level::Warn, "t-a", "Second LINE".into());
        let f = Filter {
            min_level: Some(Level::Info),
            components: vec!["t-a".into()],
            contains: "line".into(),
        };
        let (old, mut rx) = subscribe(10, &f);
        let texts: Vec<_> = old.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["first line", "Second LINE"]);
        let (last, _) = subscribe(1, &f);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].text, "Second LINE");

        emit(Level::Error, "t-a", "third line".into());
        let mut got = None;
        while let Ok(l) = rx.try_recv() {
            if f.matches(&l) {
                got = Some(l);
            }
        }
        assert_eq!(got.unwrap().text, "third line");
    }

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert!(Level::Error > Level::Info);
        assert_eq!(Level::parse("loud"), None);
    }
}
