//! janus-receiverd: the janus receiving server (server side).
//!
//! A daemon: it starts and runs, waiting for instructions from `janus-cli server …`
//! on a fixed control port.
//!
//! Arguments:
//!   (no arguments)    normal start (systemd), values from the environment
//!   --dev             foreground debug mode
//!   --listen <addr>   data plane address (receiving bands)
//!   --store <dir>     storage directory
//!   --quota <bytes>   store ceiling, 0 = no limit
//!
//! In production the parameters come from `/etc/janus/receiverd.env` via the systemd unit
//! (the variables `JANUS_LISTEN`, `JANUS_STORE`, `JANUS_QUOTA`); flags override
//! them. The control address is fixed, overridden only by
//! `JANUS_SERVER_ADDR` (dev setups, parallel instances).

use std::process::ExitCode;

use janus_receiverd::server;
use janus_receiverd::server::CONTROL_ADDR;

const DEFAULT_LISTEN: &str = "0.0.0.0:7443";
const DEFAULT_STORE: &str = "/var/lib/janus/store";

const LISTEN_ENV: &str = "JANUS_LISTEN";
const STORE_ENV: &str = "JANUS_STORE";
const QUOTA_ENV: &str = "JANUS_QUOTA";
const CONTROL_ADDR_ENV: &str = "JANUS_SERVER_ADDR";

fn main() -> ExitCode {
    // Base values: the environment (systemd EnvironmentFile), otherwise defaults.
    let mut listen = std::env::var(LISTEN_ENV).unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let mut store = std::env::var(STORE_ENV).unwrap_or_else(|_| DEFAULT_STORE.to_string());
    let mut quota: u64 = std::env::var(QUOTA_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let control_addr = std::env::var(CONTROL_ADDR_ENV).unwrap_or_else(|_| CONTROL_ADDR.to_string());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dev = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dev" => {
                dev = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            flag @ ("--listen" | "--store" | "--quota") => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("janus-receiverd: {flag} requires a value");
                    return ExitCode::from(2);
                };
                match flag {
                    "--listen" => listen = value.clone(),
                    "--store" => store = value.clone(),
                    "--quota" => match value.parse() {
                        Ok(v) => quota = v,
                        Err(_) => {
                            eprintln!("janus-receiverd: --quota: not a number: {value}");
                            return ExitCode::from(2);
                        }
                    },
                    _ => unreachable!(),
                }
                i += 2;
            }
            other => {
                eprintln!("janus-receiverd: unknown argument {other}\n");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    if dev {
        eprintln!("janus-receiverd: dev mode (foreground, no mTLS)");
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("janus-receiverd: failed to create runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(async move {
        match server::serve_dev(&listen, &store, quota, &control_addr).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("janus-receiverd: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn print_usage() {
    eprintln!(
        "janus-receiverd — janus receiver server.\n\n\
         Usage: janus-receiverd [--dev] [--listen <addr>] [--store <dir>] [--quota <bytes>]\n\n  \
         --dev     foreground debug mode\n  \
         --listen  data plane address (default {DEFAULT_LISTEN}, env {LISTEN_ENV})\n  \
         --store   storage directory (default {DEFAULT_STORE}, env {STORE_ENV})\n  \
         --quota   limit in bytes, 0 = unlimited (env {QUOTA_ENV})\n\n\
         The daemon awaits instructions on {CONTROL_ADDR}: janus-cli server status|machines|shutdown\n\
         Control address override (dev): {CONTROL_ADDR_ENV}."
    );
}
