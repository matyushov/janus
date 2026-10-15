//! janus-receiverd: the janus receiving server (server side).
//!
//! A daemon: it starts and runs, waiting for instructions from `janus-cli server …`
//! on a fixed control port.
//!
//! Arguments:
//!   (no arguments)    normal start (systemd), values from the environment; mTLS + IdentityMap
//!   --dev             foreground debug mode: plain gRPC (NO TLS), one built-in store, no identity
//!   --listen <addr>   data plane address (receiving bands)
//!   --store <dir>     storage directory
//!   --quota <bytes>   store ceiling, 0 = no limit
//!
//! In production the parameters come from `/etc/janus/receiverd.env` via the systemd unit
//! (the variables `JANUS_LISTEN`, `JANUS_STORE`, `JANUS_QUOTA`, and for the production mode
//! `JANUS_TLS_CERT`, `JANUS_TLS_KEY`, `JANUS_TLS_CA`, `JANUS_MACHINES`); flags override
//! them. Without `--dev` all four TLS/mapping variables are mandatory: the daemon refuses to
//! start rather than fall back to plain gRPC. The control address is fixed, overridden only by
//! `JANUS_SERVER_ADDR` (dev setups, parallel instances).

use std::process::ExitCode;

use janus_receiverd::server;
use janus_receiverd::server::CONTROL_ADDR;

const DEFAULT_LISTEN: &str = "0.0.0.0:7443";
const DEFAULT_STORE: &str = "/var/lib/janus/store";

const LISTEN_ENV: &str = "JANUS_LISTEN";
const STORE_ENV: &str = "JANUS_STORE";
const QUOTA_ENV: &str = "JANUS_QUOTA";
const TLS_CERT_ENV: &str = "JANUS_TLS_CERT";
const TLS_KEY_ENV: &str = "JANUS_TLS_KEY";
const TLS_CA_ENV: &str = "JANUS_TLS_CA";
const MACHINES_ENV: &str = "JANUS_MACHINES";
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

    let result = if dev {
        None
    } else {
        match prod_config(&listen, &store, quota, &control_addr) {
            Ok(cfg) => Some(cfg),
            Err(missing) => {
                eprintln!(
                    "janus-receiverd: cannot start in production mode: {missing}\n\
                     Set them (see /etc/janus/receiverd.env) or use --dev for plain gRPC without \
                     TLS (development only)."
                );
                return ExitCode::from(2);
            }
        }
    };

    rt.block_on(async move {
        let run = match result {
            Some(cfg) => server::serve_mtls(cfg).await,
            None => server::serve_dev(&listen, &store, quota, &control_addr).await,
        };
        match run {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("janus-receiverd: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Production settings from the environment; names every missing variable.
fn prod_config(
    listen: &str,
    store: &str,
    quota: u64,
    control_addr: &str,
) -> Result<server::ProdConfig, String> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (cert, key, ca, machines) = (
        get(TLS_CERT_ENV),
        get(TLS_KEY_ENV),
        get(TLS_CA_ENV),
        get(MACHINES_ENV),
    );
    let missing: Vec<&str> = [
        (TLS_CERT_ENV, cert.is_none()),
        (TLS_KEY_ENV, key.is_none()),
        (TLS_CA_ENV, ca.is_none()),
        (MACHINES_ENV, machines.is_none()),
    ]
    .into_iter()
    .filter_map(|(n, m)| m.then_some(n))
    .collect();
    if !missing.is_empty() {
        return Err(format!("missing environment: {}", missing.join(", ")));
    }
    Ok(server::ProdConfig {
        listen: listen.to_string(),
        store_root: store.to_string(),
        default_quota: quota,
        tls: janus_receiverd::tls::TlsPaths {
            cert: cert.unwrap().into(),
            key: key.unwrap().into(),
            ca: ca.unwrap().into(),
        },
        machines: machines.unwrap().into(),
        control_addr: control_addr.to_string(),
    })
}

fn print_usage() {
    eprintln!(
        "janus-receiverd — janus receiver server.\n\n\
         Usage: janus-receiverd [--dev] [--listen <addr>] [--store <dir>] [--quota <bytes>]\n\n  \
         --dev     foreground debug mode: plain gRPC, NO TLS, one built-in store (development only)\n  \
         --listen  data plane address (default {DEFAULT_LISTEN}, env {LISTEN_ENV})\n  \
         --store   storage directory (default {DEFAULT_STORE}, env {STORE_ENV}); in production the\n            \
                   parent of the per-machine store subdirectories\n  \
         --quota   limit in bytes, 0 = unlimited (env {QUOTA_ENV}); in production the default for\n            \
                   machines without their own quota\n\n\
         Production mode (no --dev) requires, from the environment:\n  \
         {TLS_CERT_ENV}   server certificate (PEM)\n  \
         {TLS_KEY_ENV}    server private key (PEM, keep it 0600)\n  \
         {TLS_CA_ENV}     CA (PEM) that signs the client certificates\n  \
         {MACHINES_ENV}   machines file (JSON, 0600): certificate fingerprint -> machine -> store -> quota\n\n\
         The daemon awaits instructions on {CONTROL_ADDR}: janus-cli server status|machines|shutdown\n\
         Control address override (dev): {CONTROL_ADDR_ENV}."
    );
}
