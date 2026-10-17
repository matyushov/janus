//! State that outlives a connection: parked durable handles and leases.
//!
//! A durable handle (DH2Q) survives a dropped TCP connection: the connection's cleanup *parks*
//! it here instead of closing it, and a new connection takes it back with DH2C within the
//! timeout. Parked handles are also written to `ParkedHandleStore` (next to the journal), so a
//! reconnect after a daemon restart works too: the backend handle is gone then and the file is
//! reopened by path.
//!
//! Leases (RqLs) are granted per lease key. A conflicting open breaks the holder's lease: the
//! holder's connection gets an unsolicited LEASE_BREAK notification (through the channel
//! registered with `register_conn`), and the opener waits for the acknowledgment — except when
//! the holder is the opener's own connection (its acknowledgment arrives on the very connection
//! that would be blocked) or has no connection (parked): those breaks apply at once.
//!
//! Everything here is synchronous under one short-lived mutex; the only waiting is
//! `wait_breaks`, which polls.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use janus_lib::jlog;
use janus_lib::journal::{ParkedHandleStore, ParkedRecord};
use janus_lib::vfs::BackendHandle;
use smb_wire::create::{
    LEASE_FLAG_PARENT_KEY_SET, LEASE_HANDLE, LEASE_READ, LEASE_WRITE, LeaseReq,
};
use smb_wire::lease::LeaseBreakNotification;
use tokio::sync::mpsc;

use crate::server::ConnId;

/// Timeout granted for `DH2Q` with Timeout = 0 (the server default the Apple validation asks for).
pub const DEFAULT_DURABLE_TIMEOUT: Duration = Duration::from_secs(60);
/// The ceiling for a requested durable timeout.
pub const MAX_DURABLE_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a lease break waits for the acknowledgment before the lease is downgraded by force.
pub const BREAK_ACK_TIMEOUT: Duration = Duration::from_secs(35);

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// A message the server sends to a connection on its own initiative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Push {
    LeaseBreak(LeaseBreakNotification),
}

/// Who is opening a file and how (the input of lease conflict detection).
#[derive(Debug, Clone, Copy)]
pub struct OpenIntent<'a> {
    pub conn: ConnId,
    pub path: &'a str,
    /// The open can read or write file data (an attributes-only open conflicts with nothing).
    pub data_access: bool,
    /// The open can write file data.
    pub writes: bool,
}

/// What `lease_for_open` decided.
#[derive(Debug, Default)]
pub struct LeaseOutcome {
    /// The lease to report in the CREATE response (`None`: no RqLs context was sent).
    pub reply: Option<LeaseReq>,
    /// Lease keys whose break the opener must wait for (`wait_breaks`).
    pub wait_for: Vec<[u8; 16]>,
}

/// A handle taken back from the parked set.
#[derive(Debug)]
pub struct Reclaimed {
    pub record: ParkedRecord,
    /// `None` after a daemon restart: the caller reopens the file by path.
    pub handle: Option<BackendHandle>,
    /// The lease the handle held, as it stands now.
    pub lease: Option<LeaseReq>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReconnectError {
    /// No such parked handle (never existed, expired, wrong FileId or CreateGuid).
    NotFound,
    /// The handle belongs to another user or client.
    Denied,
}

struct Parked {
    record: ParkedRecord,
    handle: Option<BackendHandle>,
    expires: Instant,
}

struct LeaseEntry {
    path: String,
    state: u32,
    epoch: u16,
    /// Opens that use this key.
    opens: u32,
    /// The connection to send breaks to; `None` while every open of it is parked.
    holder: Option<ConnId>,
    /// A break is outstanding: the state the holder has to go down to, and the deadline.
    breaking: Option<(u32, Instant)>,
    v2: bool,
    flags: u32,
    parent_key: [u8; 16],
}

#[derive(Default)]
struct Inner {
    /// Durable opens on live connections (persisted too, so that `kill -9` loses nothing).
    live: HashMap<[u8; 16], ParkedRecord>,
    parked: HashMap<[u8; 16], Parked>,
    leases: HashMap<[u8; 16], LeaseEntry>,
}

/// Server-wide state shared by all connections.
pub struct Shared {
    inner: Mutex<Inner>,
    store: ParkedHandleStore,
    conns: Mutex<HashMap<ConnId, mpsc::UnboundedSender<Push>>>,
    break_timeout: Duration,
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A lease state the protocol allows: none, R, RH, RW or RWH.
fn normalize(state: u32) -> u32 {
    let s = state & (LEASE_READ | LEASE_HANDLE | LEASE_WRITE);
    if s & LEASE_READ == 0 { 0 } else { s }
}

impl Default for Shared {
    fn default() -> Self {
        Shared::new(ParkedHandleStore::in_memory())
    }
}

impl Shared {
    /// Opens the store and revives the handles the previous run left parked.
    pub fn new(store: ParkedHandleStore) -> Shared {
        let mut inner = Inner::default();
        let (now, now_ms) = (Instant::now(), unix_now_ms());
        let (heartbeat, records) = store.load();
        for mut rec in records {
            // Open on a live connection when the file was written: the daemon died after the
            // last heartbeat, so the clock starts there (a handle expires `timeout` after it).
            if rec.expires_unix_ms == 0 {
                rec.expires_unix_ms = heartbeat + u64::from(rec.timeout_ms);
            }
            if rec.expires_unix_ms <= now_ms {
                continue;
            }
            let expires = now + Duration::from_millis(rec.expires_unix_ms - now_ms);
            if let Some(key) = rec.lease_key {
                let e = inner.leases.entry(key).or_insert_with(|| LeaseEntry {
                    path: rec.rel_path.clone(),
                    state: rec.lease_state,
                    epoch: 0,
                    opens: 0,
                    holder: None,
                    breaking: None,
                    v2: true,
                    flags: 0,
                    parent_key: [0; 16],
                });
                e.opens += 1;
            }
            inner.parked.insert(
                rec.create_guid,
                Parked {
                    record: rec,
                    handle: None,
                    expires,
                },
            );
        }
        Shared {
            inner: Mutex::new(inner),
            store,
            conns: Mutex::new(HashMap::new()),
            break_timeout: BREAK_ACK_TIMEOUT,
        }
    }

    /// Shorter acknowledgment timeout (tests).
    pub fn with_break_timeout(mut self, t: Duration) -> Shared {
        self.break_timeout = t;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self, inner: &Inner) {
        let mut records: Vec<ParkedRecord> =
            inner.parked.values().map(|p| p.record.clone()).collect();
        for rec in inner.live.values() {
            let mut rec = rec.clone();
            rec.expires_unix_ms = 0;
            if let Some(e) = rec.lease_key.and_then(|k| inner.leases.get(&k)) {
                rec.lease_state = e.state;
            }
            records.push(rec);
        }
        if let Err(e) = self.store.save(unix_now_ms(), &records) {
            jlog!(Warn, "smb", "cannot persist durable handles: {e}");
        }
    }

    /// A handle was made durable: remember it, so that a reconnect works even after a crash.
    /// The file is written by the next `heartbeat`.
    pub fn register_durable(&self, record: ParkedRecord) {
        self.lock().live.insert(record.create_guid, record);
    }

    /// The durable open is gone (CLOSE, LOGOFF).
    pub fn forget_durable(&self, create_guid: &[u8; 16]) {
        self.lock().live.remove(create_guid);
    }

    /// Called every second: keeps the on-disk copy of the live durable handles and its
    /// heartbeat current (it is the only thing a `kill -9` leaves behind).
    pub fn heartbeat(&self) {
        let g = self.lock();
        if !g.live.is_empty() {
            self.persist(&g);
        }
    }

    pub fn live_len(&self) -> usize {
        self.lock().live.len()
    }

    // ---- connections --------------------------------------------------------------------

    /// Registers a connection; the receiver yields what the server wants to send to it.
    pub fn register_conn(&self, conn: ConnId) -> mpsc::UnboundedReceiver<Push> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(conn, tx);
        rx
    }

    /// The connection is gone: breaks nobody can acknowledge apply at once.
    pub fn unregister_conn(&self, conn: ConnId) {
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn);
        let mut g = self.lock();
        for e in g.leases.values_mut().filter(|e| e.holder == Some(conn)) {
            e.holder = None;
            if let Some((to, _)) = e.breaking.take() {
                e.state = to;
            }
        }
    }

    // ---- leases -------------------------------------------------------------------------

    /// Breaks the leases the open conflicts with and decides the lease for the open itself.
    pub fn lease_for_open(&self, intent: OpenIntent<'_>, req: Option<&LeaseReq>) -> LeaseOutcome {
        let now = Instant::now();
        let mut pushes: Vec<(ConnId, Push)> = Vec::new();
        let mut out = LeaseOutcome::default();
        let own_key = req.map(|r| r.key);
        let mut g = self.lock();

        for (key, e) in g.leases.iter_mut() {
            if e.path != intent.path || Some(*key) == own_key {
                continue;
            }
            if e.breaking.is_none() && intent.data_access {
                let mut to = e.state;
                if e.state & LEASE_WRITE != 0 {
                    to &= !LEASE_WRITE;
                }
                if intent.writes {
                    to &= !LEASE_READ;
                }
                let to = normalize(to);
                if to != e.state {
                    e.epoch = e.epoch.wrapping_add(1);
                    match e.holder {
                        Some(holder) => {
                            e.breaking = Some((to, now + self.break_timeout));
                            pushes.push((
                                holder,
                                Push::LeaseBreak(LeaseBreakNotification {
                                    new_epoch: e.epoch,
                                    ack_required: e.state & !to & (LEASE_WRITE | LEASE_HANDLE) != 0,
                                    key: *key,
                                    current_state: e.state,
                                    new_state: to,
                                }),
                            ));
                        }
                        // Nobody to ask: a parked handle gives way at once.
                        None => e.state = to,
                    }
                }
            }
            if e.breaking.is_some() && e.holder.is_some_and(|h| h != intent.conn) {
                out.wait_for.push(*key);
            }
        }

        if let Some(req) = req {
            let others = g
                .leases
                .iter()
                .any(|(k, e)| *k != req.key && e.path == intent.path);
            let reply_state = if let Some(e) = g.leases.get_mut(&req.key) {
                if e.path == intent.path {
                    e.opens += 1;
                    e.holder = Some(intent.conn);
                    e.state
                } else {
                    0 // the key is bound to another file: no lease
                }
            } else {
                let mut granted = normalize(req.state);
                if others {
                    granted &= !LEASE_WRITE;
                }
                g.leases.insert(
                    req.key,
                    LeaseEntry {
                        path: intent.path.to_owned(),
                        state: granted,
                        epoch: req.epoch,
                        opens: 1,
                        holder: Some(intent.conn),
                        breaking: None,
                        v2: req.v2,
                        flags: req.flags & LEASE_FLAG_PARENT_KEY_SET,
                        parent_key: req.parent_key,
                    },
                );
                granted
            };
            let e = g.leases.get(&req.key);
            out.reply = Some(LeaseReq {
                key: req.key,
                state: reply_state,
                flags: if req.v2 {
                    req.flags & LEASE_FLAG_PARENT_KEY_SET
                } else {
                    0
                },
                parent_key: if req.v2 { req.parent_key } else { [0; 16] },
                epoch: e.map_or(req.epoch, |e| e.epoch),
                v2: req.v2,
            });
        }
        drop(g);

        let conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        for (conn, push) in pushes {
            if let Some(tx) = conns.get(&conn) {
                let _ = tx.send(push);
            }
        }
        out
    }

    /// Waits until the breaks of `keys` are acknowledged; after the deadline the lease is
    /// downgraded by force (the client is not answering).
    pub async fn wait_breaks(&self, keys: &[[u8; 16]]) {
        for key in keys {
            loop {
                let deadline = {
                    let mut g = self.lock();
                    match g.leases.get_mut(key) {
                        Some(e) => match e.breaking {
                            Some((to, deadline)) if Instant::now() >= deadline => {
                                e.state = to;
                                e.breaking = None;
                                break;
                            }
                            Some((_, deadline)) => deadline,
                            None => break,
                        },
                        None => break,
                    }
                };
                let _ = deadline;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    /// LEASE_BREAK acknowledgment: the state the client keeps. `Err` is an NTSTATUS.
    pub fn ack_lease(&self, key: [u8; 16], state: u32) -> Result<u32, u32> {
        let mut g = self.lock();
        let e = g.leases.get_mut(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let Some((to, _)) = e.breaking else {
            return Err(STATUS_UNSUCCESSFUL);
        };
        if state & !to != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        e.state = normalize(state);
        e.breaking = None;
        Ok(e.state)
    }

    /// One open that used `key` is gone.
    pub fn release_lease(&self, key: &[u8; 16]) {
        let mut g = self.lock();
        if let Some(e) = g.leases.get_mut(key) {
            e.opens = e.opens.saturating_sub(1);
            if e.opens == 0 {
                g.leases.remove(key);
            }
        }
    }

    /// Current state of a lease (tests, status).
    pub fn lease_state(&self, key: &[u8; 16]) -> Option<u32> {
        self.lock().leases.get(key).map(|e| e.state)
    }

    // ---- durable handles ----------------------------------------------------------------

    /// The timeout to grant for a requested one (0 = server default, capped).
    pub fn durable_timeout(requested_ms: u32) -> Duration {
        if requested_ms == 0 {
            DEFAULT_DURABLE_TIMEOUT
        } else {
            Duration::from_millis(u64::from(requested_ms)).min(MAX_DURABLE_TIMEOUT)
        }
    }

    /// The connection dropped with a durable handle open: keep it for `timeout`.
    pub fn park(&self, mut record: ParkedRecord, handle: BackendHandle, timeout: Duration) {
        let mut g = self.lock();
        g.live.remove(&record.create_guid);
        if let Some(key) = record.lease_key
            && let Some(e) = g.leases.get_mut(&key)
        {
            record.lease_state = e.state;
            e.holder = None;
            if let Some((to, _)) = e.breaking.take() {
                e.state = to;
                record.lease_state = to;
            }
        }
        record.expires_unix_ms = unix_now_ms() + timeout.as_millis() as u64;
        g.parked.insert(
            record.create_guid,
            Parked {
                record,
                handle: Some(handle),
                expires: Instant::now() + timeout,
            },
        );
        self.persist(&g);
    }

    /// DH2C: take a parked handle back. Only its owner (user and client) may.
    pub fn reconnect(
        &self,
        file_id: [u8; 16],
        create_guid: [u8; 16],
        owner: &str,
        client_guid: [u8; 16],
        conn: ConnId,
    ) -> Result<Reclaimed, ReconnectError> {
        let mut g = self.lock();
        let p = g.parked.get(&create_guid).ok_or(ReconnectError::NotFound)?;
        if p.expires <= Instant::now() || p.record.file_id != file_id {
            return Err(ReconnectError::NotFound);
        }
        if p.record.owner != owner || p.record.client_guid != client_guid {
            return Err(ReconnectError::Denied);
        }
        let p = g.parked.remove(&create_guid).expect("checked above");
        let lease = p.record.lease_key.and_then(|key| {
            let e = g.leases.get_mut(&key)?;
            e.holder = Some(conn);
            Some(LeaseReq {
                key,
                state: e.state,
                flags: e.flags,
                parent_key: e.parent_key,
                epoch: e.epoch,
                v2: e.v2,
            })
        });
        self.persist(&g);
        Ok(Reclaimed {
            record: p.record,
            handle: p.handle,
            lease,
        })
    }

    /// Removes the parked handles whose time is up; the caller closes the returned backend handles.
    pub fn take_expired(&self, now: Instant) -> Vec<BackendHandle> {
        let mut g = self.lock();
        let due: Vec<[u8; 16]> = g
            .parked
            .iter()
            .filter(|(_, p)| p.expires <= now)
            .map(|(k, _)| *k)
            .collect();
        let mut handles = Vec::new();
        for guid in &due {
            if let Some(p) = g.parked.remove(guid) {
                handles.extend(p.handle);
                if let Some(key) = p.record.lease_key
                    && let Some(e) = g.leases.get_mut(&key)
                {
                    e.opens = e.opens.saturating_sub(1);
                    if e.opens == 0 {
                        g.leases.remove(&key);
                    }
                }
            }
        }
        if !due.is_empty() {
            self.persist(&g);
        }
        handles
    }

    pub fn parked_len(&self) -> usize {
        self.lock().parked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];

    fn rq(key: [u8; 16], state: u32) -> LeaseReq {
        LeaseReq {
            key,
            state,
            flags: 0,
            parent_key: [0; 16],
            epoch: 1,
            v2: true,
        }
    }

    fn intent(conn: u64, path: &str, data: bool, writes: bool) -> OpenIntent<'_> {
        OpenIntent {
            conn: ConnId(conn),
            path,
            data_access: data,
            writes,
        }
    }

    fn record(guid: u8, lease: Option<[u8; 16]>) -> ParkedRecord {
        ParkedRecord {
            create_guid: [guid; 16],
            file_id: [guid; 16],
            client_guid: [9; 16],
            owner: "janus".into(),
            rel_path: "f".into(),
            access: 0x12019f,
            delete_pending: false,
            lease_key: lease,
            lease_state: 0,
            timeout_ms: 60_000,
            expires_unix_ms: 0,
        }
    }

    #[test]
    fn lease_is_granted_as_requested_and_shared_by_key() {
        let s = Shared::default();
        let o = s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        assert_eq!(o.reply.unwrap().state, 7);
        // a second open with the same key sees the same lease
        let o = s.lease_for_open(intent(1, "f", true, false), Some(&rq(A, 1)));
        assert_eq!(o.reply.unwrap().state, 7);
        assert!(o.wait_for.is_empty());
        s.release_lease(&A);
        assert_eq!(s.lease_state(&A), Some(7), "one open still uses it");
        s.release_lease(&A);
        assert_eq!(s.lease_state(&A), None);
    }

    #[test]
    fn invalid_states_are_normalized_and_a_second_key_gets_no_write() {
        let s = Shared::default();
        assert_eq!(
            s.lease_for_open(intent(1, "f", false, false), Some(&rq(A, LEASE_HANDLE)))
                .reply
                .unwrap()
                .state,
            0
        );
        assert_eq!(
            s.lease_for_open(intent(1, "g", false, false), Some(&rq(B, 7)))
                .reply
                .unwrap()
                .state,
            7
        );
        let c = [3; 16];
        // a different key on a file that is already leased never gets W
        let o = s.lease_for_open(intent(1, "g", false, false), Some(&rq(c, 7)));
        assert_eq!(o.reply.unwrap().state, LEASE_READ | LEASE_HANDLE);
    }

    #[test]
    fn attribute_only_open_breaks_nothing() {
        let s = Shared::default();
        let _rx = s.register_conn(ConnId(1));
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        let o = s.lease_for_open(intent(2, "f", false, false), None);
        assert!(o.wait_for.is_empty());
        assert_eq!(s.lease_state(&A), Some(7));
    }

    #[tokio::test]
    async fn conflicting_open_breaks_the_holder_and_waits_for_the_ack() {
        let s = std::sync::Arc::new(Shared::default());
        let mut rx = s.register_conn(ConnId(1));
        let _rx2 = s.register_conn(ConnId(2));
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        let o = s.lease_for_open(intent(2, "f", true, false), Some(&rq(B, 3)));
        assert_eq!(o.wait_for, vec![A]);
        let Push::LeaseBreak(n) = rx.try_recv().expect("break pushed to the holder");
        assert_eq!((n.key, n.current_state, n.new_state), (A, 7, 3));
        assert!(n.ack_required);
        // the new lease has no W (the file is leased by another key)
        assert_eq!(o.reply.unwrap().state, 3);
        let s2 = std::sync::Arc::clone(&s);
        let waiter = tokio::spawn(async move { s2.wait_breaks(&[A]).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "waits for the acknowledgment");
        assert_eq!(s.ack_lease(A, 3), Ok(3));
        waiter.await.unwrap();
        assert_eq!(s.lease_state(&A), Some(3));
        // acknowledging again, or for an unknown key, is an error
        assert_eq!(s.ack_lease(A, 3), Err(STATUS_UNSUCCESSFUL));
        assert_eq!(s.ack_lease([7; 16], 0), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    }

    #[tokio::test]
    async fn ack_may_not_raise_the_state_and_silence_downgrades_by_force() {
        let s = Shared::default().with_break_timeout(Duration::from_millis(40));
        let _rx = s.register_conn(ConnId(1));
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        let o = s.lease_for_open(intent(2, "f", true, true), None);
        assert_eq!(o.wait_for, vec![A]);
        // a writer takes R away as well
        assert_eq!(s.ack_lease(A, 7), Err(STATUS_INVALID_PARAMETER));
        s.wait_breaks(&[A]).await;
        assert_eq!(s.lease_state(&A), Some(0));
    }

    #[test]
    fn a_break_on_the_openers_own_connection_does_not_block_it() {
        let s = Shared::default();
        let mut rx = s.register_conn(ConnId(1));
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        let o = s.lease_for_open(intent(1, "f", true, false), Some(&rq(B, 3)));
        assert!(o.wait_for.is_empty());
        assert!(rx.try_recv().is_ok(), "the notification is still sent");
    }

    #[test]
    fn a_lease_of_a_parked_handle_gives_way_at_once() {
        let s = Shared::default();
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        s.park(
            record(1, Some(A)),
            BackendHandle(5),
            Duration::from_secs(60),
        );
        let o = s.lease_for_open(intent(2, "f", true, false), Some(&rq(B, 3)));
        assert!(o.wait_for.is_empty());
        assert_eq!(s.lease_state(&A), Some(3));
    }

    #[test]
    fn park_and_reconnect_by_the_owner_only() {
        let s = Shared::default();
        s.park(record(1, None), BackendHandle(5), Duration::from_secs(60));
        assert_eq!(s.parked_len(), 1);
        let (g, f) = ([1; 16], [1; 16]);
        assert_eq!(
            s.reconnect(f, [2; 16], "janus", [9; 16], ConnId(2))
                .unwrap_err(),
            ReconnectError::NotFound
        );
        assert_eq!(
            s.reconnect([3; 16], g, "janus", [9; 16], ConnId(2))
                .unwrap_err(),
            ReconnectError::NotFound
        );
        assert_eq!(
            s.reconnect(f, g, "mallory", [9; 16], ConnId(2))
                .unwrap_err(),
            ReconnectError::Denied
        );
        assert_eq!(
            s.reconnect(f, g, "janus", [8; 16], ConnId(2)).unwrap_err(),
            ReconnectError::Denied
        );
        let r = s.reconnect(f, g, "janus", [9; 16], ConnId(2)).unwrap();
        assert_eq!(r.handle, Some(BackendHandle(5)));
        assert_eq!(s.parked_len(), 0);
        // a handle can be taken back once
        assert_eq!(
            s.reconnect(f, g, "janus", [9; 16], ConnId(2)).unwrap_err(),
            ReconnectError::NotFound
        );
    }

    #[test]
    fn parked_handles_expire_and_release_their_lease() {
        let s = Shared::default();
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        s.park(
            record(1, Some(A)),
            BackendHandle(5),
            Duration::from_millis(10),
        );
        assert!(s.take_expired(Instant::now()).is_empty());
        let later = Instant::now() + Duration::from_secs(1);
        assert_eq!(s.take_expired(later), vec![BackendHandle(5)]);
        assert_eq!(s.parked_len(), 0);
        assert_eq!(s.lease_state(&A), None);
        // and an expired handle cannot be reclaimed even before the sweeper ran
        s.park(record(2, None), BackendHandle(6), Duration::ZERO);
        assert_eq!(
            s.reconnect([2; 16], [2; 16], "janus", [9; 16], ConnId(1))
                .unwrap_err(),
            ReconnectError::NotFound
        );
    }

    #[test]
    fn parked_handles_survive_a_restart_without_their_backend_handle() {
        let dir = std::env::temp_dir().join(format!("janus-parked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Shared::new(ParkedHandleStore::in_dir(&dir).unwrap());
        s.lease_for_open(intent(1, "f", true, true), Some(&rq(A, 7)));
        s.park(
            record(1, Some(A)),
            BackendHandle(5),
            Duration::from_secs(60),
        );
        s.park(record(2, None), BackendHandle(6), Duration::ZERO);
        drop(s);
        let s = Shared::new(ParkedHandleStore::in_dir(&dir).unwrap());
        assert_eq!(s.parked_len(), 1, "the expired one is not revived");
        assert_eq!(s.lease_state(&A), Some(7));
        let r = s
            .reconnect([1; 16], [1; 16], "janus", [9; 16], ConnId(7))
            .unwrap();
        assert_eq!(r.handle, None);
        assert_eq!(r.record.rel_path, "f");
        assert_eq!(r.lease.unwrap().state, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_timeout_defaults_and_is_capped() {
        assert_eq!(Shared::durable_timeout(0), DEFAULT_DURABLE_TIMEOUT);
        assert_eq!(Shared::durable_timeout(30_000), Duration::from_secs(30));
        assert_eq!(Shared::durable_timeout(u32::MAX), MAX_DURABLE_TIMEOUT);
    }
}
