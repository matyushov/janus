//! Argument parsing for janus-cli. The first positional argument is the SIDE:
//! `client` (janus-smbd, the `SmbFrontControl` contract) or
//! `server` (janus-receiverd, the `ReceiverControl` contract).
//! Subcommands map 1:1 to the RPCs of the corresponding service (janus-proto).
//!
//! The control channel address is NOT set by a flag: the daemons always run on
//! fixed loopback ports. Overriding is only through the environment
//! (non-standard setups, parallel instances in tests).
//!
//! The parser is hand-written and deliberately simple (no clap): if it grows, we move
//! to clap and keep the interface.

use std::path::PathBuf;

/// Fixed addresses of the control plane (always loopback).
/// 50051 is the de facto standard gRPC port, 50052 is next to it; both are outside the range
/// the OS hands out for outgoing connections.
pub const CLIENT_ADDR: &str = "127.0.0.1:50051";
pub const SERVER_ADDR: &str = "127.0.0.1:50052";

/// Environment variables for overriding (dev setups, tests).
pub const CLIENT_ADDR_ENV: &str = "JANUS_CLIENT_ADDR";
pub const SERVER_ADDR_ENV: &str = "JANUS_SERVER_ADDR";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Client side: janus-smbd (the SMB gateway).
    Client,
    /// Server side: janus-receiverd (the receiver).
    Server,
}

impl Target {
    /// Daemon address: an environment variable, otherwise the fixed default.
    pub fn addr(self) -> String {
        let (env_key, default) = match self {
            Target::Client => (CLIENT_ADDR_ENV, CLIENT_ADDR),
            Target::Server => (SERVER_ADDR_ENV, SERVER_ADDR),
        };
        std::env::var(env_key).unwrap_or_else(|_| default.to_string())
    }

    pub fn name(self) -> &'static str {
        match self {
            Target::Client => "client",
            Target::Server => "server",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cli {
    pub target: Target,
    pub command: Command,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    // --- common to both sides ---
    /// `status [--watch [<sec>]]` → Status of the corresponding service; with `--watch` it is
    /// redrawn every `<sec>` seconds (default 1) until Ctrl-C.
    Status {
        watch: Option<std::time::Duration>,
    },
    /// `events` → WatchEvents (a stream to stdout, Ctrl-C to exit).
    Events,
    /// `diag --out <path>` → GetDiagnostics: a tar.gz into a file.
    Diag {
        out: PathBuf,
    },
    /// `shutdown [--drain]` → Shutdown (`--drain` for client only).
    Shutdown {
        drain: bool,
    },

    // --- client only (SmbFrontControl) ---
    /// `ready` → EnsureReady: exit 0/1 + blocker.
    Ready,
    /// `configure …` → Configure: the receiver server, the mTLS identity, the share.
    Configure(ConfigureArgs),
    /// `drain [--timeout <sec>]` → Drain: push everything not yet uploaded to the server.
    Drain {
        timeout_sec: u32,
    },
    /// `logs [-f] [-n N] [--level L] [--component a,b] [--grep TEXT]` → StreamLogs.
    Logs(LogsArgs),
    /// `quiesce` / `resume` → the write gate.
    Quiesce,
    Resume,

    // --- server only (ReceiverControl) ---
    /// `machines` → ListMachines: store directories, quotas, active workers.
    Machines,
}

/// Parameters of `client configure`. Required: endpoint + client-cert +
/// client-key + ca; the rest have defaults.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigureArgs {
    pub endpoint: String,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub ca: PathBuf,
    /// Share name in the mount point smb://127.0.0.1:{port}/{share}.
    pub share: String,
    /// Mount point port (the loopback host is fixed). 0 = the daemon default.
    pub mount_port: u32,
    /// `--journal on|off`; `None` = the daemon default (on).
    pub journal: Option<bool>,
    /// `--journal-dir`; empty = `<state-dir>/journal`.
    pub journal_dir: String,
    /// `--max-backlog <MiB>`; 0 = the default (1024).
    pub max_backlog_mib: u64,
    /// `--flush-policy local-journal`: fsync = fsync of the journal (unsafe for backups).
    pub local_journal: bool,
    /// `--interim-after <ms>`, `--max-wait <sec>`, `--down-after <sec>`; 0 = the daemon default.
    pub interim_after_ms: u32,
    pub max_wait_sec: u32,
    pub down_after_sec: u32,
}

/// Parameters of `client logs` (the daemon's log, like `tail`).
#[derive(Debug, PartialEq, Eq)]
pub struct LogsArgs {
    /// `-f` / `--follow`: keep streaming new lines.
    pub follow: bool,
    /// `-n N`: how many of the latest lines to show first (default 100).
    pub tail: u32,
    /// `--level debug|info|warn|error`: the lowest level shown (default info).
    pub level: u32,
    /// `--component smb,daemon,backend,control`: only these (default all).
    pub components: Vec<String>,
    /// `--grep TEXT`: only lines containing it (case-insensitive).
    pub grep: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

pub const USAGE: &str = "\
janus-cli — janus daemon management

Usage: janus-cli <client|server> <command> [options]

Sides:
  client     janus-smbd — SMB gateway (127.0.0.1:50051)
  server     janus-receiverd — receiver (127.0.0.1:50052)

Commands (both sides):
  status [--watch [<sec>]]  daemon status (--watch redraws it every <sec>, default 1)
  events                    event stream
  diag --out <path>         dump a diagnostic bundle
  shutdown [--drain]        stop the daemon (--drain is client-only)

Commands (client only):
  ready                     check connectivity to the server (exit 0 = ready)
  configure --endpoint <host:port> --client-cert <pem> --client-key <pem>
            --ca <pem> [--share <name>] [--port <n>]
            [--journal on|off] [--journal-dir <path>] [--max-backlog <MiB>]
            [--flush-policy sync-through|local-journal]
                            set the receiver server, mTLS identity and
                            the mount point smb://127.0.0.1:<port>/<share>
                            (--port is for display only; the real SMB address
                            is set by the daemon environment: JANUS_SMB_ADDR)
                            --journal off = every write goes to the server at once;
                            --max-backlog = unuploaded data the journal may hold (default 1024);
                            local-journal = fsync only syncs the journal: UNSAFE for backups
            [--interim-after <ms>] [--max-wait <sec>] [--down-after <sec>]
                            how long a FLUSH/CLOSE/RENAME may keep the SMB client waiting for the
                            server: interim (still working) reply after <ms> (default 1500); an
                            error after <sec> (600); an error early if the server has been
                            failing for <sec> (120)
  logs [-f] [-n <N>] [--level debug|info|warn|error] [--component <a,b>] [--grep <text>]
                            the daemon log, like tail: the last N lines (default 100) and with
                            -f new ones as they appear; components: smb, daemon, backend, control
  drain [--timeout <sec>]   flush pending data (default 300)
  quiesce | resume          pause/resume accepting writes

Commands (server only):
  machines                  list machines: store, quotas, active workers

Daemon addresses are fixed; override (dev/tests) via the
environment variables JANUS_CLIENT_ADDR and JANUS_SERVER_ADDR.
";

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, ParseError> {
    let mut args = args.into_iter().peekable();

    let target = match args.next().as_deref() {
        Some("client") => Target::Client,
        Some("server") => Target::Server,
        Some(other) => {
            return Err(ParseError(format!(
                "unknown side: {other} (expected client | server)"
            )));
        }
        None => return Err(ParseError("side not specified (client | server)".into())),
    };

    let cmd = args
        .next()
        .ok_or_else(|| ParseError("command not specified".into()))?;

    let command = match (target, cmd.as_str()) {
        // common
        (_, "status") => {
            let mut watch = None;
            if optional_flag(&mut args, "--watch") {
                let secs = match args.peek() {
                    Some(v) if !v.starts_with('-') => {
                        let v = args.next().expect("peeked");
                        v.parse::<f64>()
                            .ok()
                            .filter(|s| *s >= 0.1)
                            .ok_or_else(|| ParseError(format!("--watch: bad interval: {v}")))?
                    }
                    _ => 1.0,
                };
                watch = Some(std::time::Duration::from_secs_f64(secs));
            }
            Command::Status { watch }
        }
        (_, "events") => Command::Events,
        (_, "diag") => Command::Diag {
            out: required_value(&mut args, "--out", "diag")?.into(),
        },
        (Target::Client, "shutdown") => Command::Shutdown {
            drain: optional_flag(&mut args, "--drain"),
        },
        (Target::Server, "shutdown") => {
            if args.peek().map(String::as_str) == Some("--drain") {
                return Err(ParseError(
                    "--drain does not apply to server (it has no journal)".into(),
                ));
            }
            Command::Shutdown { drain: false }
        }

        // client only
        (Target::Client, "ready") => Command::Ready,
        (Target::Client, "quiesce") => Command::Quiesce,
        (Target::Client, "resume") => Command::Resume,
        (Target::Client, "configure") => {
            let mut f = collect_flags(&mut args)?;
            let mount_port = match f.remove("--port") {
                Some(v) => v
                    .parse()
                    .map_err(|_| ParseError(format!("--port: not a number: {v}")))?,
                None => 0, // daemon default
            };
            let cfg = ConfigureArgs {
                endpoint: take_required(&mut f, "--endpoint")?,
                client_cert: take_required(&mut f, "--client-cert")?.into(),
                client_key: take_required(&mut f, "--client-key")?.into(),
                ca: take_required(&mut f, "--ca")?.into(),
                share: f.remove("--share").unwrap_or_else(|| "backup".into()),
                mount_port,
                journal: match f.remove("--journal").as_deref() {
                    None => None,
                    Some("on") => Some(true),
                    Some("off") => Some(false),
                    Some(v) => {
                        return Err(ParseError(format!("--journal: expected on|off, got {v}")));
                    }
                },
                journal_dir: f.remove("--journal-dir").unwrap_or_default(),
                max_backlog_mib: match f.remove("--max-backlog") {
                    Some(v) => v
                        .parse()
                        .map_err(|_| ParseError(format!("--max-backlog: not a number: {v}")))?,
                    None => 0,
                },
                local_journal: match f.remove("--flush-policy").as_deref() {
                    None | Some("sync-through") => false,
                    Some("local-journal") => true,
                    Some(v) => {
                        return Err(ParseError(format!(
                            "--flush-policy: expected sync-through|local-journal, got {v}"
                        )));
                    }
                },
                interim_after_ms: 0,
                max_wait_sec: 0,
                down_after_sec: 0,
            };
            let mut number = |name: &str| -> Result<u32, ParseError> {
                match f.remove(name) {
                    Some(v) => v
                        .parse()
                        .map_err(|_| ParseError(format!("{name}: not a number: {v}"))),
                    None => Ok(0),
                }
            };
            let cfg = ConfigureArgs {
                interim_after_ms: number("--interim-after")?,
                max_wait_sec: number("--max-wait")?,
                down_after_sec: number("--down-after")?,
                ..cfg
            };
            if let Some((unknown, _)) = f.into_iter().next() {
                return Err(ParseError(format!("configure: unknown flag {unknown}")));
            }
            // the configure flags were consumed entirely: nothing left to check in the tail
            return Ok(Cli {
                target,
                command: Command::Configure(cfg),
            });
        }
        (Target::Client, "logs") => {
            let mut a = LogsArgs {
                follow: false,
                tail: 100,
                level: 1,
                components: Vec::new(),
                grep: String::new(),
            };
            while let Some(flag) = args.peek().cloned() {
                let value = |args: &mut std::iter::Peekable<_>| -> Result<String, ParseError> {
                    args.next();
                    args.next()
                        .ok_or_else(|| ParseError(format!("{flag} requires a value")))
                };
                match flag.as_str() {
                    "-f" | "--follow" => {
                        args.next();
                        a.follow = true;
                    }
                    "-n" => {
                        let v = value(&mut args)?;
                        a.tail = v
                            .parse()
                            .map_err(|_| ParseError(format!("-n: not a number: {v}")))?;
                    }
                    "--level" => {
                        let v = value(&mut args)?;
                        a.level = match v.to_ascii_lowercase().as_str() {
                            "debug" => 0,
                            "info" => 1,
                            "warn" | "warning" => 2,
                            "error" => 3,
                            _ => {
                                return Err(ParseError(format!(
                                    "--level: expected debug|info|warn|error, got {v}"
                                )));
                            }
                        };
                    }
                    "--component" => {
                        let v = value(&mut args)?;
                        a.components = v
                            .split(',')
                            .filter(|c| !c.is_empty())
                            .map(str::to_owned)
                            .collect();
                    }
                    "--grep" => a.grep = value(&mut args)?,
                    _ => break,
                }
            }
            Command::Logs(a)
        }
        (Target::Client, "drain") => {
            let timeout_sec = match optional_value(&mut args, "--timeout")? {
                Some(v) => v
                    .parse()
                    .map_err(|_| ParseError(format!("--timeout: not a number: {v}")))?,
                None => 300,
            };
            Command::Drain { timeout_sec }
        }

        // server only
        (Target::Server, "machines") => Command::Machines,

        (target, other) => {
            return Err(ParseError(format!(
                "command \"{other}\" is not supported by side {}",
                target.name()
            )));
        }
    };

    if let Some(extra) = args.next() {
        return Err(ParseError(format!("unexpected argument: {extra}")));
    }

    Ok(Cli { target, command })
}

/// Collect all remaining `--flag value` pairs into a map (for commands with a set of
/// named flags in arbitrary order, for example configure).
fn collect_flags(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<std::collections::HashMap<String, String>, ParseError> {
    let mut map = std::collections::HashMap::new();
    while let Some(flag) = args.next() {
        if !flag.starts_with("--") {
            return Err(ParseError(format!("expected --flag, got: {flag}")));
        }
        let value = args
            .next()
            .ok_or_else(|| ParseError(format!("{flag} requires a value")))?;
        if map.insert(flag.clone(), value).is_some() {
            return Err(ParseError(format!("flag {flag} given twice")));
        }
    }
    Ok(map)
}

fn take_required(
    map: &mut std::collections::HashMap<String, String>,
    flag: &str,
) -> Result<String, ParseError> {
    map.remove(flag)
        .ok_or_else(|| ParseError(format!("configure requires {flag} <value>")))
}

fn required_value(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
    cmd: &str,
) -> Result<String, ParseError> {
    match optional_value(args, flag)? {
        Some(v) => Ok(v),
        None => Err(ParseError(format!("{cmd} requires {flag} <value>"))),
    }
}

fn optional_value(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<Option<String>, ParseError> {
    if args.peek().map(String::as_str) == Some(flag) {
        args.next();
        let v = args
            .next()
            .ok_or_else(|| ParseError(format!("{flag} requires a value")))?;
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn optional_flag(args: &mut std::iter::Peekable<impl Iterator<Item = String>>, flag: &str) -> bool {
    if args.peek().map(String::as_str) == Some(flag) {
        args.next();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Cli {
        parse(args.iter().map(|s| s.to_string())).expect("parse ok")
    }

    #[test]
    fn client_status_uses_fixed_addr() {
        let cli = parse_ok(&["client", "status"]);
        assert_eq!(cli.target, Target::Client);
        assert_eq!(cli.command, Command::Status { watch: None });
        assert_eq!(Target::Client.addr(), CLIENT_ADDR);
    }

    #[test]
    fn server_has_its_own_addr() {
        let cli = parse_ok(&["server", "status"]);
        assert_eq!(cli.target, Target::Server);
        assert_eq!(Target::Server.addr(), SERVER_ADDR);
        assert_ne!(CLIENT_ADDR, SERVER_ADDR);
    }

    #[test]
    fn client_drain_default_and_explicit_timeout() {
        assert_eq!(
            parse_ok(&["client", "drain"]).command,
            Command::Drain { timeout_sec: 300 }
        );
        assert_eq!(
            parse_ok(&["client", "drain", "--timeout", "60"]).command,
            Command::Drain { timeout_sec: 60 }
        );
    }

    #[test]
    fn shutdown_drain_only_for_client() {
        assert_eq!(
            parse_ok(&["client", "shutdown", "--drain"]).command,
            Command::Shutdown { drain: true }
        );
        assert!(parse(["server", "shutdown", "--drain"].map(String::from)).is_err());
        assert_eq!(
            parse_ok(&["server", "shutdown"]).command,
            Command::Shutdown { drain: false }
        );
    }

    #[test]
    fn configure_parses_flags_in_any_order_with_defaults() {
        let cli = parse_ok(&[
            "client",
            "configure",
            "--client-key",
            "k.pem",
            "--endpoint",
            "vault:7443",
            "--ca",
            "ca.pem",
            "--client-cert",
            "c.pem",
        ]);
        assert_eq!(
            cli.command,
            Command::Configure(ConfigureArgs {
                endpoint: "vault:7443".into(),
                client_cert: PathBuf::from("c.pem"),
                client_key: PathBuf::from("k.pem"),
                ca: PathBuf::from("ca.pem"),
                share: "backup".into(),
                mount_port: 0,
                journal: None,
                journal_dir: String::new(),
                max_backlog_mib: 0,
                local_journal: false,
                interim_after_ms: 0,
                max_wait_sec: 0,
                down_after_sec: 0,
            })
        );
    }

    #[test]
    fn status_watch_and_logs_flags() {
        use std::time::Duration;
        let c = parse_ok(&["client", "status", "--watch"]);
        assert_eq!(
            c.command,
            Command::Status {
                watch: Some(Duration::from_secs(1))
            }
        );
        let c = parse_ok(&["server", "status", "--watch", "0.5"]);
        assert_eq!(
            c.command,
            Command::Status {
                watch: Some(Duration::from_millis(500))
            }
        );
        assert!(parse(["client", "status", "--watch", "x"].map(String::from)).is_err());

        let c = parse_ok(&["client", "logs"]);
        let Command::Logs(a) = c.command else {
            panic!("logs expected")
        };
        assert_eq!((a.follow, a.tail, a.level), (false, 100, 1));
        let c = parse_ok(&[
            "client",
            "logs",
            "-f",
            "-n",
            "20",
            "--level",
            "warn",
            "--component",
            "smb,daemon",
            "--grep",
            "async",
        ]);
        let Command::Logs(a) = c.command else {
            panic!("logs expected")
        };
        assert_eq!(
            (a.follow, a.tail, a.level, a.grep.as_str()),
            (true, 20, 2, "async")
        );
        assert_eq!(a.components, ["smb", "daemon"]);
        assert!(parse(["client", "logs", "--level", "loud"].map(String::from)).is_err());
        assert!(parse(["server", "logs"].map(String::from)).is_err());
    }

    #[test]
    fn configure_wait_flags() {
        let cli = parse_ok(&[
            "client",
            "configure",
            "--endpoint",
            "v:1",
            "--client-cert",
            "c",
            "--client-key",
            "k",
            "--ca",
            "a",
            "--interim-after",
            "500",
            "--max-wait",
            "90",
            "--down-after",
            "30",
        ]);
        let Command::Configure(a) = cli.command else {
            panic!("configure expected")
        };
        assert_eq!(
            (a.interim_after_ms, a.max_wait_sec, a.down_after_sec),
            (500, 90, 30)
        );
    }

    #[test]
    fn configure_journal_flags() {
        let base = [
            "client",
            "configure",
            "--endpoint",
            "v:1",
            "--client-cert",
            "c",
            "--client-key",
            "k",
            "--ca",
            "ca",
        ];
        let with = |extra: &[&str]| {
            let mut v: Vec<&str> = base.to_vec();
            v.extend_from_slice(extra);
            parse(v.into_iter().map(String::from))
        };
        let a = match with(&[
            "--journal",
            "off",
            "--journal-dir",
            "/j",
            "--max-backlog",
            "256",
            "--flush-policy",
            "local-journal",
        ])
        .unwrap()
        .command
        {
            Command::Configure(a) => a,
            _ => panic!(),
        };
        assert_eq!(a.journal, Some(false));
        assert_eq!(
            (a.journal_dir.as_str(), a.max_backlog_mib, a.local_journal),
            ("/j", 256, true)
        );
        assert!(with(&["--journal", "maybe"]).is_err());
        assert!(with(&["--max-backlog", "lots"]).is_err());
        assert!(with(&["--flush-policy", "fast"]).is_err());
    }

    #[test]
    fn configure_accepts_port_and_share() {
        let cli = parse_ok(&[
            "client",
            "configure",
            "--endpoint",
            "v:1",
            "--client-cert",
            "c",
            "--client-key",
            "k",
            "--ca",
            "ca",
            "--share",
            "tm",
            "--port",
            "4445",
        ]);
        match cli.command {
            Command::Configure(a) => {
                assert_eq!(a.share, "tm");
                assert_eq!(a.mount_port, 4445);
            }
            _ => panic!("expected Configure"),
        }
    }

    #[test]
    fn configure_requires_all_tls_flags_and_rejects_unknown() {
        assert!(
            parse(
                [
                    "client",
                    "configure",
                    "--endpoint",
                    "v:1",
                    "--client-cert",
                    "c",
                    "--ca",
                    "ca"
                ]
                .map(String::from)
            )
            .is_err()
        );
        assert!(
            parse(
                [
                    "client",
                    "configure",
                    "--endpoint",
                    "v:1",
                    "--client-cert",
                    "c",
                    "--client-key",
                    "k",
                    "--ca",
                    "ca",
                    "--bogus",
                    "x"
                ]
                .map(String::from)
            )
            .is_err()
        );
    }

    #[test]
    fn side_specific_commands_rejected_for_wrong_side() {
        assert!(parse(["server", "drain"].map(String::from)).is_err());
        assert!(parse(["server", "ready"].map(String::from)).is_err());
        assert!(parse(["client", "machines"].map(String::from)).is_err());
    }

    #[test]
    fn missing_or_unknown_side_rejected() {
        assert!(parse(std::iter::empty()).is_err());
        assert!(parse(["frobnicate", "status"].map(String::from)).is_err());
        assert!(parse(["status"].map(String::from)).is_err());
        // the old names are no longer accepted
        assert!(parse(["smbd", "status"].map(String::from)).is_err());
        assert!(parse(["receiver", "status"].map(String::from)).is_err());
    }
}
