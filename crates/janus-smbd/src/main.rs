//! janus-smbd: the janus SMB gateway (client side).
//!
//! A daemon: it starts and runs, waiting for instructions from `janus-cli client …`
//! on a fixed control port. The receiving server, the mount point and
//! the share parameters arrive with the `configure` command and are not
//! set by startup parameters.
//!
//! Arguments:
//!   (no arguments)    normal start (systemd/launchd)
//!   --dev             foreground debug mode: verbose output, does not
//!                     daemonize, does not wait for socket activation
//!
//! The configuration is persisted (`JANUS_CONFIG`, default `~/.config/janus/config`, 0600) and
//! restored on start.
//!
//! Addresses are overridden only through the environment (dev setups, parallel
//! instances): `JANUS_CLIENT_ADDR` is control, `JANUS_SMB_ADDR` is the SMB listener
//! (there is no `--smb-port` flag).
//!
//! SMB user: `JANUS_SMB_USER`/`JANUS_SMB_PASSWORD` (dev) or the file
//! `JANUS_SMB_CREDS_FILE` / `~/.config/janus/smb-credentials` (mode 0600;
//! created by `janus-cli client configure`). There is no guest access.
//!
//! All the logic lives in the `janus-client` library; this binary reads the environment and
//! waits for a shutdown request.

mod launchd;

use janus_client::{Client, ClientConfig, ExitReason, StopMode};
use janus_lib::jlog;

/// The share host is a model invariant (SMB does not leave the machine). Not a parameter.
const HOST: &str = "127.0.0.1";
/// Control address: `janus-cli client` talks here. Symmetric to the server (50052).
const CONTROL_ADDR: &str = "127.0.0.1:50051";
/// Default SMB listener. 445 is taken by the system SMB server on Windows and
/// needs privileges, so for debugging we take a high port.
const SMB_PORT: u16 = 4445;
const BONJOUR_ENV: &str = "JANUS_BONJOUR";
const TRACE_ENV: &str = "JANUS_SMB_TRACE";

/// Overrides for dev setups and tests.
const CONTROL_ADDR_ENV: &str = "JANUS_CLIENT_ADDR";
const SMB_ADDR_ENV: &str = "JANUS_SMB_ADDR";
/// Directory served by the local backend instead of the receiver (dev only).
const LOCAL_ROOT_ENV: &str = "JANUS_SMB_LOCAL_ROOT";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut dev = false;
    for arg in &args {
        match arg.as_str() {
            "--dev" => dev = true,
            "-h" | "--help" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("janus-smbd: unknown argument {other}\n");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    std::process::exit(run(dev));
}

fn print_usage() {
    eprintln!(
        "janus-smbd — janus SMB gateway.\n\n\
         Usage: janus-smbd [--dev]\n\n  \
         --dev    foreground debug mode (verbose output)\n\n\
         The daemon awaits instructions on {CONTROL_ADDR}. Setup:\n  \
         janus-cli client configure --endpoint <host:port> --client-cert <pem> \\\n    \
         --client-key <pem> --ca <pem> [--share <name>] [--port <n>]\n\n\
         Address overrides (dev): {CONTROL_ADDR_ENV}, {SMB_ADDR_ENV}.\n\
         Share directory (dev only): {LOCAL_ROOT_ENV} serves a local folder instead of the receiver.\n\
         SMB user: JANUS_SMB_USER/JANUS_SMB_PASSWORD or the JANUS_SMB_CREDS_FILE file."
    );
}

/// Everything the old daemon took from the environment, as explicit configuration.
fn config_from_env() -> ClientConfig {
    let config_file = janus_lib::config::default_path();
    if config_file.is_none() {
        jlog!(
            Warn,
            "daemon",
            "no config path (set JANUS_CONFIG); configuration is not persisted"
        );
    }
    ClientConfig {
        state_dir: janus_lib::config::state_dir(),
        config_file,
        smb_listen: std::env::var(SMB_ADDR_ENV).unwrap_or_else(|_| format!("{HOST}:{SMB_PORT}")),
        allow_non_loopback: true,
        control_listen: Some(
            std::env::var(CONTROL_ADDR_ENV).unwrap_or_else(|_| CONTROL_ADDR.to_string()),
        ),
        smb_user: std::env::var(janus_lib::credentials::USER_ENV).ok(),
        smb_password: std::env::var(janus_lib::credentials::PASSWORD_ENV).ok(),
        smb_credentials_file: janus_lib::credentials::default_path(),
        // `janus-cli client configure` creates the account.
        generate_credentials: false,
        local_root: std::env::var_os(LOCAL_ROOT_ENV).map(std::path::PathBuf::from),
        bonjour: true,
        bonjour_without_share: std::env::var(BONJOUR_ENV).as_deref() == Ok("1"),
        trace: match std::env::var(TRACE_ENV).as_deref() {
            Ok("1") => 1,
            Ok("2") => 2,
            _ => 0,
        },
        ..ClientConfig::default()
    }
}

/// The exit code of the process.
fn run(dev: bool) -> i32 {
    let client = match Client::start(config_from_env()) {
        Ok(c) => c,
        Err(e) => {
            jlog!(Error, "daemon", "{e}");
            return 1;
        }
    };
    if dev {
        jlog!(
            Info,
            "daemon",
            "dev mode; configure with: janus-cli client configure …"
        );
    }
    // The failure of either plane is fatal for the daemon.
    match client.wait() {
        ExitReason::ShutdownRequested => {
            jlog!(Info, "daemon", "stopping on shutdown command");
            // Let the gRPC reply to Shutdown reach the client.
            std::thread::sleep(std::time::Duration::from_millis(200));
            client.stop(StopMode::Immediate);
            0
        }
        // Both planes log their own failure.
        ExitReason::ControlStopped(_) | ExitReason::SmbStopped(_) => {
            client.stop(StopMode::Immediate);
            1
        }
    }
}
