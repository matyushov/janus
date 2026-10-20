//! The C ABI called from Rust through its `extern "C"` surface, in one process
//! (one client per process, so the tests take turns).

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::net::TcpListener;
use std::sync::{Mutex, MutexGuard};

use janus::*;

static TURN: Mutex<()> = Mutex::new(());
fn turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(|e| e.into_inner())
}

fn config(dir: &std::path::Path) -> CString {
    CString::new(format!(
        r#"{{"version":1,"client":{{"local_root":{:?},"log_stderr":false}}}}"#,
        dir.display().to_string()
    ))
    .unwrap()
}

fn last_error() -> String {
    let mut buf = [0 as c_char; 256];
    let n = unsafe { janus_last_error(buf.as_mut_ptr(), buf.len()) };
    assert!(n < buf.len());
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("janus-ffi-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

unsafe fn json_of(f: impl FnOnce(*mut *mut c_char) -> c_int) -> serde_json::Value {
    let mut out: *mut c_char = std::ptr::null_mut();
    assert_eq!(f(&mut out), JANUS_OK, "{}", last_error());
    let v = serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
    unsafe { janus_free_string(out) };
    v
}

#[test]
fn full_cycle() {
    let _t = turn();
    unsafe {
        assert_eq!(janus_client_abi_version(), JANUS_ABI_VERSION);
        assert!(!CStr::from_ptr(janus_client_version()).to_bytes().is_empty());
        let cfg = config(&tmp("cycle"));
        let mut c = std::ptr::null_mut();
        assert_eq!(
            janus_client_start(cfg.as_ptr(), None, std::ptr::null_mut(), &mut c),
            JANUS_OK
        );
        let info = json_of(|o| janus_client_mount_info(c, o));
        assert!(
            info["url"]
                .as_str()
                .unwrap()
                .starts_with("smb://127.0.0.1:")
        );
        assert_eq!(info["password"].as_str().unwrap().len(), 32);
        let st = json_of(|o| janus_client_status_json(c, o));
        assert_eq!(st["configured"], false);
        assert_eq!(st["log_dropped"], 0);
        assert_eq!(janus_client_ready(c), JANUS_E_NOT_READY);
        assert!(last_error().contains("no-config"));
        assert_eq!(janus_client_drain(c, 500), JANUS_OK);
        let bad = CString::new("{}").unwrap();
        assert_eq!(
            janus_client_configure(c, bad.as_ptr()),
            JANUS_E_INVALID_CONFIG
        );
        assert_eq!(janus_client_stop(c, 0), JANUS_OK);
    }
}

#[test]
fn argument_errors_do_not_crash() {
    let _t = turn();
    unsafe {
        let mut c = std::ptr::null_mut();
        let none = std::ptr::null_mut();
        assert_eq!(
            janus_client_start(std::ptr::null(), None, none, &mut c),
            JANUS_E_INVALID_ARG
        );
        assert_eq!(
            janus_client_start(c"{}".as_ptr(), None, none, std::ptr::null_mut()),
            JANUS_E_INVALID_ARG
        );
        let bad_utf8 = [0xffu8 as c_char, 0];
        assert_eq!(
            janus_client_start(bad_utf8.as_ptr(), None, none, &mut c),
            JANUS_E_INVALID_ARG
        );
        assert_eq!(
            janus_client_start(c"{ nope".as_ptr(), None, none, &mut c),
            JANUS_E_INVALID_CONFIG
        );
        assert!(last_error().contains("config JSON"));
        assert_eq!(
            janus_client_ready(std::ptr::null_mut()),
            JANUS_E_INVALID_ARG
        );
        assert_eq!(
            janus_client_stop(std::ptr::null_mut(), 0),
            JANUS_E_INVALID_ARG
        );
        janus_free_string(std::ptr::null_mut());
        // a failed start left the process free to start
        let cfg = config(&tmp("args"));
        assert_eq!(
            janus_client_start(cfg.as_ptr(), None, none, &mut c),
            JANUS_OK
        );
        assert_eq!(
            janus_client_start(cfg.as_ptr(), None, none, &mut std::ptr::null_mut()),
            JANUS_E_ALREADY_STARTED
        );
        assert_eq!(janus_client_stop(c, 0), JANUS_OK);
    }
}

#[test]
fn busy_port_is_bind_error() {
    let _t = turn();
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = CString::new(format!(
        r#"{{"client":{{"local_root":{:?},"smb_listen":"{}"}}}}"#,
        tmp("busy").display().to_string(),
        blocker.local_addr().unwrap()
    ))
    .unwrap();
    let mut c = std::ptr::null_mut();
    assert_eq!(
        unsafe { janus_client_start(cfg.as_ptr(), None, std::ptr::null_mut(), &mut c) },
        JANUS_E_BIND
    );
    assert!(c.is_null());
}

extern "C-unwind" fn panicking_log(
    _l: c_int,
    _c: *const c_char,
    _m: *const c_char,
    user: *mut c_void,
) {
    unsafe { &*(user as *const std::sync::atomic::AtomicUsize) }
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    panic!("callback panics");
}

extern "C-unwind" fn stopping_log(
    _l: c_int,
    _c: *const c_char,
    _m: *const c_char,
    user: *mut c_void,
) {
    let slot = unsafe { &*(user as *const std::sync::atomic::AtomicI32) };
    // the handle is passed through a global below
    let h = HANDLE.load(std::sync::atomic::Ordering::SeqCst) as *mut janus_client;
    if !h.is_null() {
        slot.store(
            unsafe { janus_client_stop(h, 0) },
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

static HANDLE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[test]
fn panicking_callback_does_not_kill_the_process() {
    let _t = turn();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    unsafe {
        let cfg = config(&tmp("panic"));
        let mut c = std::ptr::null_mut();
        let user = &calls as *const _ as *mut c_void;
        assert_eq!(
            janus_client_start(cfg.as_ptr(), Some(panicking_log), user, &mut c),
            JANUS_OK
        );
        assert_eq!(janus_client_stop(c, 0), JANUS_OK);
    }
    assert!(
        calls.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the callback ran"
    );
}

#[test]
fn stop_from_the_callback_is_refused() {
    let _t = turn();
    let result = std::sync::atomic::AtomicI32::new(i32::MAX);
    unsafe {
        let cfg = config(&tmp("cbstop"));
        let mut c = std::ptr::null_mut();
        let user = &result as *const _ as *mut c_void;
        // Lines are queued before the handle exists, so publish it before the first delivery
        // can matter: the callback only acts when HANDLE is set.
        assert_eq!(
            janus_client_start(cfg.as_ptr(), Some(stopping_log), user, &mut c),
            JANUS_OK
        );
        HANDLE.store(c as usize, std::sync::atomic::Ordering::SeqCst);
        // provoke a log line after the handle is published
        assert_eq!(
            janus_client_configure(c, c"{}".as_ptr()),
            JANUS_E_INVALID_CONFIG
        );
        let mut tries = 0;
        while result.load(std::sync::atomic::Ordering::SeqCst) == i32::MAX && tries < 100 {
            // the client logs on drain/ready paths too
            janus_client_drain(c, 10);
            std::thread::sleep(std::time::Duration::from_millis(20));
            tries += 1;
        }
        HANDLE.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(janus_client_stop(c, 0), JANUS_OK);
    }
    let r = result.load(std::sync::atomic::Ordering::SeqCst);
    // either the callback never ran after publication (nothing to assert) or it was refused
    assert!(r == i32::MAX || r == JANUS_E_CALLBACK_CONTEXT, "got {r}");
}

#[test]
fn twenty_cycles_do_not_leak_threads() {
    let _t = turn();
    fn threads() -> usize {
        #[cfg(target_os = "linux")]
        {
            return std::fs::read_dir("/proc/self/task")
                .map(|d| d.count())
                .unwrap_or(0);
        }
        #[allow(unreachable_code)]
        {
            0
        }
    }
    let before = threads();
    for i in 0..20 {
        unsafe {
            let cfg = config(&tmp(&format!("loop{}", i % 2)));
            let mut c = std::ptr::null_mut();
            assert_eq!(
                janus_client_start(cfg.as_ptr(), None, std::ptr::null_mut(), &mut c),
                JANUS_OK
            );
            assert_eq!(janus_client_stop(c, 0), JANUS_OK);
        }
    }
    if before > 0 {
        assert!(
            threads() <= before + 1,
            "threads grew from {before} to {}",
            threads()
        );
    }
}
