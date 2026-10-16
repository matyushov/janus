//! janus-cli: management of the janus daemons.
//!
//! Model: the daemons run permanently and wait for instructions on fixed
//! loopback addresses; the CLI picks a side with the first argument and sends the command
//! to the corresponding daemon:
//!   `client` → janus-smbd    (127.0.0.1:50051, the SmbFrontControl contract)
//!   `server` → janus-receiverd (127.0.0.1:50052, the ReceiverControl contract)
//!
//! The daemons do not distinguish the CLI from the orchestrator: there is one contract.

mod cli;

use cli::{Cli, Command, ConfigureArgs, ParseError, Target, USAGE};
use janus_proto::v1::receiver_control_client::ReceiverControlClient;
use janus_proto::v1::smb_front_control_client::SmbFrontControlClient;
use janus_proto::v1::{ConfigureRequest, Empty};
use tonic::transport::Channel;

/// Exit codes: 0 ok, 1 daemon refusal / not ready, 2 usage, 3 no connection to the daemon.
mod exit {
    pub const NOT_READY: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const NO_DAEMON: i32 = 3;
}

fn main() {
    let cli = match cli::parse(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(ParseError(msg)) => {
            eprintln!("janus-cli: {msg}\n\n{USAGE}");
            std::process::exit(exit::USAGE);
        }
    };

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(run(cli));
}

/// Connect to the daemon of the chosen side.
async fn connect(target: Target) -> Channel {
    let addr = target.addr();
    let uri = format!("http://{addr}");
    match Channel::from_shared(uri.clone()) {
        Ok(ep) => match ep.connect().await {
            Ok(ch) => ch,
            Err(e) => {
                eprintln!(
                    "janus-cli: daemon {} unavailable at {addr}: {e}",
                    target.name()
                );
                eprintln!(
                    "  is {} running? (dev: {} --dev)",
                    daemon_binary(target),
                    daemon_binary(target)
                );
                std::process::exit(exit::NO_DAEMON);
            }
        },
        Err(e) => {
            eprintln!("janus-cli: invalid address {addr}: {e}");
            std::process::exit(exit::USAGE);
        }
    }
}

fn daemon_binary(target: Target) -> &'static str {
    match target {
        Target::Client => "janus-smbd",
        Target::Server => "janus-receiverd",
    }
}

async fn run(cli: Cli) {
    match cli.target {
        Target::Client => run_client(cli.command).await,
        Target::Server => run_server(cli.command).await,
    }
}

// ============================================================================
// Client side: janus-smbd
// ============================================================================

async fn run_client(cmd: Command) {
    let channel = connect(Target::Client).await;
    let mut c = SmbFrontControlClient::new(channel);

    match cmd {
        Command::Configure(args) => {
            let req = build_configure(&args);
            match c.configure(req).await {
                Ok(reply) => {
                    let ack = reply.into_inner();
                    if ack.ok {
                        let port = effective_mount_port(
                            args.mount_port,
                            std::env::var("JANUS_SMB_ADDR").ok().as_deref(),
                        );
                        println!(
                            "janus-smbd configured: server {}, share smb://127.0.0.1:{}/{}",
                            args.endpoint, port, args.share
                        );
                        println!("connectivity check: janus-cli client ready");
                    } else {
                        eprintln!(
                            "janus-cli: daemon rejected the configuration: {}",
                            ack.error
                        );
                        std::process::exit(exit::NOT_READY);
                    }
                }
                Err(e) => fail_rpc(e),
            }
        }
        Command::Ready => match c.ensure_ready(Empty {}).await {
            Ok(reply) => {
                let r = reply.into_inner();
                if r.ready {
                    println!("janus-smbd ready: connected to the server");
                } else {
                    eprintln!("janus-smbd NOT ready: {}", r.blocker);
                    std::process::exit(exit::NOT_READY);
                }
            }
            Err(e) => fail_rpc(e),
        },
        Command::Status => match c.status(Empty {}).await {
            Ok(reply) => {
                let s = reply.into_inner();
                println!("version:           {}", s.version);
                println!("SMB sessions:      {}", s.smb_sessions);
                println!("open handles:      {}", s.open_handles);
                println!("parked durables:   {}", s.durable_handles_parked);
                println!("journal backlog:   {} bytes", s.journal_backlog_bytes);
                println!(
                    "oldest unuploaded: {}",
                    if s.journal_backlog_bytes == 0 {
                        "-".to_string()
                    } else {
                        format!("{:.1} s ago", s.oldest_unuploaded_age_ms as f64 / 1000.0)
                    }
                );
                println!("uploaded:          {} bytes", s.uploaded_bytes_total);
                println!("upload errors:     {}", s.upload_errors);
                println!("stuck files:       {}", s.sticky_error_files);
                if !s.last_upload_error.is_empty() {
                    println!("last upload error: {}", s.last_upload_error);
                }
                if s.last_appliance_ack_unix_ms > 0 {
                    let ago = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0)
                        - s.last_appliance_ack_unix_ms;
                    println!("last server ack:   {:.1} s ago", ago.max(0) as f64 / 1000.0);
                }
            }
            Err(e) => fail_rpc(e),
        },
        Command::Quiesce => match c.quiesce(Empty {}).await {
            Ok(_) => println!("janus-smbd: writes paused"),
            Err(e) => fail_rpc(e),
        },
        Command::Resume => match c.resume(Empty {}).await {
            Ok(_) => println!("janus-smbd: writes resumed"),
            Err(e) => fail_rpc(e),
        },
        Command::Drain { timeout_sec } => {
            match c.drain(janus_proto::v1::DrainRequest { timeout_sec }).await {
                Ok(r) => {
                    let r = r.into_inner();
                    println!(
                        "janus-smbd: drain {} ({} bytes left)",
                        if r.drained { "complete" } else { "incomplete" },
                        r.remaining_bytes
                    );
                    if !r.drained {
                        std::process::exit(exit::NOT_READY);
                    }
                }
                Err(e) => fail_rpc(e),
            }
        }
        Command::Shutdown { drain } => {
            match c
                .shutdown(janus_proto::v1::ShutdownRequest { drain_first: drain })
                .await
            {
                Ok(reply) => {
                    let ack = reply.into_inner();
                    if ack.ok {
                        println!("janus-smbd: shutdown requested");
                    } else {
                        eprintln!("janus-cli: {}", ack.error);
                        std::process::exit(exit::NOT_READY);
                    }
                }
                Err(e) => fail_rpc(e),
            }
        }
        Command::Events | Command::Diag { .. } => {
            eprintln!("janus-cli: command not implemented by the daemon yet");
            std::process::exit(exit::NOT_READY);
        }
        Command::Machines => unreachable!("machines is rejected by the parser for client"),
    }
}

/// Mount point port for output: the explicit `--port`, otherwise the real port of
/// the daemon's SMB listener (`JANUS_SMB_ADDR` if set in the CLI environment, otherwise 4445).
fn effective_mount_port(requested: u32, smb_addr_env: Option<&str>) -> String {
    if requested != 0 {
        return requested.to_string();
    }
    smb_addr_env
        .and_then(|a| a.rsplit(':').next())
        .filter(|p| p.parse::<u16>().is_ok())
        .unwrap_or("4445")
        .to_string()
}

fn build_configure(args: &ConfigureArgs) -> ConfigureRequest {
    let ca_pem = match std::fs::read(&args.ca) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("janus-cli: cannot read --ca {}: {e}", args.ca.display());
            std::process::exit(exit::USAGE);
        }
    };
    for (flag, path) in [
        ("--client-cert", &args.client_cert),
        ("--client-key", &args.client_key),
    ] {
        if !path.exists() {
            eprintln!("janus-cli: {flag} not found: {}", path.display());
            std::process::exit(exit::USAGE);
        }
    }

    ConfigureRequest {
        appliance_endpoint: args.endpoint.clone(),
        client_cert_path: args.client_cert.to_string_lossy().into_owned(),
        client_key_path: args.client_key.to_string_lossy().into_owned(),
        ca_pem,
        share_name: args.share.clone(),
        mount_port: args.mount_port,
        flush_policy: if args.local_journal { 2 } else { 1 },
        journal_enabled: args.journal,
        journal_dir: args.journal_dir.clone(),
        max_backlog_bytes: args.max_backlog_mib << 20,
        ..Default::default()
    }
}

// ============================================================================
// Server side: janus-receiverd
// ============================================================================

async fn run_server(cmd: Command) {
    let channel = connect(Target::Server).await;
    let mut c = ReceiverControlClient::new(channel);

    match cmd {
        Command::Status => match c.status(Empty {}).await {
            Ok(reply) => {
                let s = reply.into_inner();
                println!("version:           {}", s.version);
                println!("active workers:    {}", s.active_workers);
                println!("known machines:    {}", s.machines_known);
                println!("gRPC sessions:     {}", s.grpc_sessions);
                println!("received:          {} bytes", s.received_bytes_total);
                println!("write errors:      {}", s.write_errors);
            }
            Err(e) => fail_rpc(e),
        },
        Command::Machines => match c.list_machines(Empty {}).await {
            Ok(reply) => {
                let list = reply.into_inner().machines;
                if list.is_empty() {
                    println!("no machines");
                    return;
                }
                println!(
                    "{:<20} {:<40} {:>12} {:>12}  worker",
                    "MACHINE", "STORE", "USED", "QUOTA"
                );
                for m in list {
                    println!(
                        "{:<20} {:<40} {:>12} {:>12}  {}",
                        m.machine_id,
                        m.store_path,
                        m.used_bytes,
                        if m.quota_bytes == 0 {
                            "—".to_string()
                        } else {
                            m.quota_bytes.to_string()
                        },
                        if m.worker_active { "active" } else { "—" }
                    );
                }
            }
            Err(e) => fail_rpc(e),
        },
        Command::Shutdown { .. } => match c.shutdown(Empty {}).await {
            Ok(reply) => {
                let ack = reply.into_inner();
                if ack.ok {
                    println!("janus-receiverd: shutdown requested");
                } else {
                    eprintln!("janus-cli: {}", ack.error);
                    std::process::exit(exit::NOT_READY);
                }
            }
            Err(e) => fail_rpc(e),
        },
        Command::Events | Command::Diag { .. } => {
            eprintln!("janus-cli: command not implemented by the daemon yet");
            std::process::exit(exit::NOT_READY);
        }
        _ => unreachable!("client commands are rejected by the parser for server"),
    }
}

fn fail_rpc(e: tonic::Status) -> ! {
    eprintln!("janus-cli: daemon refused: {}", e.message());
    std::process::exit(exit::NOT_READY);
}

#[cfg(test)]
mod tests {
    use super::effective_mount_port;

    #[test]
    fn mount_port_prefers_explicit_then_env_then_default() {
        assert_eq!(effective_mount_port(5555, Some("127.0.0.1:4446")), "5555");
        assert_eq!(effective_mount_port(0, Some("127.0.0.1:4446")), "4446");
        assert_eq!(effective_mount_port(0, Some("garbage")), "4445");
        assert_eq!(effective_mount_port(0, None), "4445");
    }
}
