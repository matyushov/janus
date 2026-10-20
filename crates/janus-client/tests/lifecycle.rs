//! Client lifecycle in one process: start, stop, start again; errors instead of exits.
//! One client per process, so the tests take turns.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use janus_client::{Client, ClientConfig, ClientError, ExitReason, StopMode};

static TURN: Mutex<()> = Mutex::new(());

fn turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(|e| e.into_inner())
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("janus-client-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn dev_config(name: &str) -> ClientConfig {
    ClientConfig {
        local_root: Some(tmpdir(name)),
        log_stderr: false,
        ..ClientConfig::default()
    }
}

#[test]
fn start_stop_and_start_again() {
    let _t = turn();
    for i in 0..3 {
        let c = Client::start(dev_config(&format!("cycle{i}"))).unwrap();
        let info = c.mount_info().unwrap();
        assert_eq!(info.host, "127.0.0.1");
        assert!(info.port != 0);
        assert!(info.url.starts_with("smb://127.0.0.1:"));
        assert!(!info.user.is_empty() && info.password.len() == 32);
        // the listener answers
        std::net::TcpStream::connect(c.smb_addr()).unwrap();
        let report = c.stop(StopMode::Immediate);
        assert!(report.drained);
    }
}

#[test]
fn stop_frees_the_port_at_once() {
    let _t = turn();
    let c = Client::start(dev_config("port")).unwrap();
    let addr = c.smb_addr();
    // an idle connection must not keep the port busy after stop
    let _conn = std::net::TcpStream::connect(addr).unwrap();
    c.stop(StopMode::Immediate);
    TcpListener::bind(addr).expect("port is free after stop");
}

#[test]
fn second_start_is_refused_until_stop() {
    let _t = turn();
    let c = Client::start(dev_config("twice")).unwrap();
    assert_eq!(
        Client::start(dev_config("twice2")).unwrap_err(),
        ClientError::AlreadyStarted
    );
    c.stop(StopMode::Immediate);
    Client::start(dev_config("twice3"))
        .unwrap()
        .stop(StopMode::Immediate);
}

#[test]
fn drop_stops_the_client() {
    let _t = turn();
    let c = Client::start(dev_config("drop")).unwrap();
    let addr = c.smb_addr();
    drop(c);
    TcpListener::bind(addr).expect("port is free after drop");
    Client::start(dev_config("drop2"))
        .unwrap()
        .stop(StopMode::Immediate);
}

#[test]
fn busy_port_is_a_bind_error_and_leaves_nothing_behind() {
    let _t = turn();
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = dev_config("busy");
    cfg.smb_listen = blocker.local_addr().unwrap().to_string();
    let e = Client::start(cfg).unwrap_err();
    assert!(matches!(e, ClientError::Bind(_)), "{e:?}");
    // a busy control port as well
    let mut cfg = dev_config("busy2");
    cfg.control_listen = Some(blocker.local_addr().unwrap().to_string());
    let e = Client::start(cfg).unwrap_err();
    assert!(matches!(e, ClientError::Bind(_)), "{e:?}");
    // the process is free to start a client afterwards
    Client::start(dev_config("busy3"))
        .unwrap()
        .stop(StopMode::Immediate);
}

#[test]
fn invalid_configuration_is_an_error_not_a_panic() {
    let _t = turn();
    let dir = tmpdir("invalid");

    let mut cfg = dev_config("inv1");
    cfg.smb_listen = "not an address".into();
    assert!(Client::start(cfg).is_err());

    let mut cfg = dev_config("inv2");
    cfg.smb_listen = String::new();
    assert!(matches!(
        Client::start(cfg).unwrap_err(),
        ClientError::InvalidConfig(_)
    ));

    // a broken config file
    let bad = dir.join("config");
    std::fs::write(&bad, "{ not json").unwrap();
    let mut cfg = dev_config("inv3");
    cfg.config_file = Some(bad);
    assert!(matches!(
        Client::start(cfg).unwrap_err(),
        ClientError::InvalidConfig(_)
    ));

    // a share that fails validation (no endpoint)
    let mut cfg = dev_config("inv4");
    cfg.share = Some(janus_lib::config::ShareConfig::default());
    assert!(matches!(
        Client::start(cfg).unwrap_err(),
        ClientError::InvalidConfig(_)
    ));

    // a share "directory" that is a file
    let file = dir.join("a-file");
    std::fs::write(&file, "x").unwrap();
    let mut cfg = dev_config("inv5");
    cfg.local_root = Some(file);
    assert!(matches!(
        Client::start(cfg).unwrap_err(),
        ClientError::InvalidConfig(_)
    ));

    // SMB must stay on loopback unless the daemon says otherwise
    let mut cfg = dev_config("inv6");
    cfg.smb_listen = "0.0.0.0:0".into();
    assert!(matches!(
        Client::start(cfg).unwrap_err(),
        ClientError::InvalidConfig(_)
    ));

    // and none of it left the process "started"
    Client::start(dev_config("inv7"))
        .unwrap()
        .stop(StopMode::Immediate);
}

#[test]
fn unconfigured_client_reports_it() {
    let _t = turn();
    let c = Client::start(dev_config("status")).unwrap();
    let st = c.status().unwrap();
    assert!(!st.configured);
    assert_eq!(st.journal_backlog_bytes, 0);
    assert_eq!(
        c.ready().unwrap_err(),
        ClientError::NotReady("no-config".into())
    );
    c.drain(Duration::from_secs(1)).unwrap();
    // an invalid share is refused and the client keeps running
    let e = c
        .configure(janus_lib::config::ShareConfig::default())
        .unwrap_err();
    assert!(matches!(e, ClientError::InvalidConfig(_)), "{e:?}");
    assert!(c.status().is_ok());
    c.stop(StopMode::Drain(Duration::from_secs(1)));
}

#[test]
fn password_is_stable_with_a_state_dir_and_never_logged() {
    let _t = turn();
    let dir = tmpdir("state");
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink_lines = Arc::clone(&lines);
    let cfg = || ClientConfig {
        state_dir: Some(dir.clone()),
        local_root: Some(dir.join("share")),
        log_sink: Some(Arc::new({
            let l = Arc::clone(&sink_lines);
            move |line: &janus_client::Line| l.lock().unwrap().push(line.text.clone())
        })),
        log_stderr: false,
        ..ClientConfig::default()
    };
    std::fs::create_dir_all(dir.join("share")).unwrap();
    let c = Client::start(cfg()).unwrap();
    let first = c.mount_info().unwrap();
    c.stop(StopMode::Immediate);
    let c = Client::start(cfg()).unwrap();
    let second = c.mount_info().unwrap();
    c.stop(StopMode::Immediate);
    assert_eq!(first.password, second.password);
    assert_eq!(first.user, second.user);

    let seen = lines.lock().unwrap().clone();
    assert!(seen.iter().any(|l| l.contains("SMB on")), "{seen:?}");
    assert!(
        !seen.iter().any(|l| l.contains(&first.password)),
        "password leaked into the log"
    );
    // the sink is gone after stop
    let n = seen.len();
    janus_lib::jlog!(Info, "test", "after stop");
    assert_eq!(lines.lock().unwrap().len(), n);
}

#[test]
fn shutdown_command_ends_wait() {
    use janus_proto::v1::ShutdownRequest;
    use janus_proto::v1::smb_front_control_client::SmbFrontControlClient;
    let _t = turn();
    let mut cfg = dev_config("shutdown");
    cfg.control_listen = Some("127.0.0.1:0".into());
    let c = Client::start(cfg).unwrap();
    let addr = c.control_addr().expect("control plane is on");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut cli = SmbFrontControlClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        let ack = cli
            .shutdown(ShutdownRequest { drain_first: false })
            .await
            .unwrap()
            .into_inner();
        assert!(ack.ok);
    });
    assert_eq!(c.wait(), ExitReason::ShutdownRequested);
    c.stop(StopMode::Immediate);
}

/// The library must report errors, never end the process or look at the environment.
#[test]
fn no_process_exit_or_env_in_library_code() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    for krate in ["janus-client", "janus-lib", "smb-core"] {
        let mut stack = vec![root.join(krate).join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    // test modules live at the end of the file; only look above them
                    let code = text.split("#[cfg(test)]").next().unwrap();
                    for (n, line) in code.lines().enumerate() {
                        let l = line.trim_start();
                        if l.starts_with("//") {
                            continue;
                        }
                        assert!(
                            !l.contains("process::exit"),
                            "{}:{}: process::exit in library code",
                            path.display(),
                            n + 1
                        );
                    }
                }
            }
        }
    }
}
