//! WAL: the point of local durability and the read overlay (read-your-writes).
//!
//! Invariants:
//! - READ must see not-yet-uploaded writes → `read_overlay` (merging the WAL
//!   on top of data from the appliance);
//! - later-wins: overlapping writes collapse in `DirtyIndex` BEFORE upload,
//!   so reordering non-overlapping ranges on the network is safe;
//! - the segment fsync mode depends on FlushPolicy (LOCAL_JOURNAL: fsync of the WAL =
//!   the answer to F_FULLFSYNC; SYNC_THROUGH: the WAL is transit+overlay, `flush` waits for
//!   the appliance and the WAL itself is never fsynced);
//! - `ParkedHandleStore` (durable handles) is J4 and is not implemented here.
//!
//! # On-disk format
//!
//! The journal directory (0700) holds append-only segments `seg-<id>.wal` (~64 MiB, 0600) and
//! a `watermark` file. A segment is a 16-byte header (`JANUSWAL`, version, reserved) followed by
//! records. A record is a fixed 36-byte header and a payload:
//!
//! ```text
//! kind u8 | pad[3] | seq u64 | file u32 | offset u64 | len u32 | data_crc u32 | header_crc u32
//! ```
//!
//! all little-endian; `header_crc` covers the first 32 bytes, `data_crc` the payload.
//! Kinds: `Write` (payload = data), `Path` (payload = the UTF-8 path of `file`; re-emitted in
//! every segment that uses the file, so trimming old segments never loses the path table) and
//! `Drop` (the dirty bytes of `file` at or after `offset` are discarded: delete / truncate).
//!
//! # Watermark and recovery
//!
//! The *watermark* W is the highest seq such that no live (not yet acknowledged and not
//! superseded) byte has a seq ≤ W. It is persisted (atomically) before a segment is deleted and
//! before the gateway changes receiver state in a way that replaying old records would undo.
//! Recovery scans every segment, checks both CRCs, cuts a torn tail of the last segment,
//! replays the records with seq > W into the `DirtyIndex` (later-wins) and continues with a
//! fresh segment. Replaying a record that had already reached the receiver is harmless:
//! `WriteRange` is idempotent.
//!
//! The journal holds user data in the clear (no encryption); the protection is the 0700/0600
//! permissions of its files.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Monotonic WAL record number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(pub u64);

/// Interned path (there are thousands of band paths, so a string in every record is wasteful).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathId(pub u32);

/// Where a range physically lives: a segment + the data offset within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loc {
    pub segment: u32,
    pub data_offset: u64,
    pub seq: Seq,
}

/// A piece of the read_overlay reply: either data from the WAL, or a hole that has to be
/// read through from the appliance.
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk {
    Wal { offset: u64, data: Vec<u8> },
    Missing { offset: u64, len: u64 },
}

// ---- format -------------------------------------------------------------------------------

const SEG_MAGIC: &[u8; 8] = b"JANUSWAL";
const SEG_VERSION: u32 = 1;
const SEG_HEADER_LEN: u64 = 16;
const REC_HEADER_LEN: usize = 36;
const WATERMARK_MAGIC: &[u8; 8] = b"JANUSWM1";
const WATERMARK_FILE: &str = "watermark";
/// Default segment size.
pub const SEGMENT_SIZE: u64 = 64 << 20;

const KIND_WRITE: u8 = 1;
const KIND_PATH: u8 = 2;
const KIND_DROP: u8 = 3;

/// Decoded record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub kind: u8,
    pub seq: Seq,
    pub file: PathId,
    pub offset: u64,
    pub len: u32,
    pub data_crc: u32,
}

impl RecordHeader {
    fn encode(&self) -> [u8; REC_HEADER_LEN] {
        let mut b = [0u8; REC_HEADER_LEN];
        b[0] = self.kind;
        b[4..12].copy_from_slice(&self.seq.0.to_le_bytes());
        b[12..16].copy_from_slice(&self.file.0.to_le_bytes());
        b[16..24].copy_from_slice(&self.offset.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..32].copy_from_slice(&self.data_crc.to_le_bytes());
        let crc = crc32fast::hash(&b[..32]);
        b[32..36].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// `None` = the bytes are not a valid header (torn or corrupt).
    fn decode(b: &[u8; REC_HEADER_LEN]) -> Option<RecordHeader> {
        let crc = u32::from_le_bytes(b[32..36].try_into().ok()?);
        if crc32fast::hash(&b[..32]) != crc {
            return None;
        }
        let kind = b[0];
        if !matches!(kind, KIND_WRITE | KIND_PATH | KIND_DROP) {
            return None;
        }
        Some(RecordHeader {
            kind,
            seq: Seq(u64::from_le_bytes(b[4..12].try_into().ok()?)),
            file: PathId(u32::from_le_bytes(b[12..16].try_into().ok()?)),
            offset: u64::from_le_bytes(b[16..24].try_into().ok()?),
            len: u32::from_le_bytes(b[24..28].try_into().ok()?),
            data_crc: u32::from_le_bytes(b[28..32].try_into().ok()?),
        })
    }
}

fn segment_name(id: u32) -> String {
    format!("seg-{id:08x}.wal")
}

fn parse_segment_name(name: &str) -> Option<u32> {
    let hex = name.strip_prefix("seg-")?.strip_suffix(".wal")?;
    if hex.len() != 8 {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

fn segment_header() -> [u8; SEG_HEADER_LEN as usize] {
    let mut h = [0u8; SEG_HEADER_LEN as usize];
    h[..8].copy_from_slice(SEG_MAGIC);
    h[8..12].copy_from_slice(&SEG_VERSION.to_le_bytes());
    h
}

fn read_exact_at(f: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(f, buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = f.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(())
    }
}

fn open_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_file_opts() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// tmp file → (fsync) → rename; the file keeps mode 0600.
fn write_atomic(path: &Path, body: &[u8], durable: bool) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let r = (|| {
        let mut f = private_file_opts()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(body)?;
        if durable {
            f.sync_all()?;
        }
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

// ---- the dirty index ----------------------------------------------------------------------

/// A contiguous dirty byte range of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub len: u32,
    /// `loc.data_offset` points at the first byte of THIS interval (it moves when one is split).
    pub loc: Loc,
}

/// A piece of the coverage answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Piece {
    Dirty { offset: u64, len: u32, loc: Loc },
    Missing { offset: u64, len: u64 },
}

/// `offset + len` does not fit into u64.
#[derive(Debug, PartialEq, Eq)]
pub struct RangeOverflow;

#[derive(Debug, Clone, Copy)]
struct LedgerEntry {
    bytes: u64,
    since: Instant,
}

/// Live bytes per record seq: gives the lowest live seq (→ the watermark), the age of the
/// oldest live record and the total.
#[derive(Debug, Default, Clone)]
struct SeqLedger {
    by_seq: BTreeMap<u64, LedgerEntry>,
    total: u64,
}

impl SeqLedger {
    fn add(&mut self, seq: u64, bytes: u64) {
        self.by_seq
            .entry(seq)
            .and_modify(|e| e.bytes += bytes)
            .or_insert_with(|| LedgerEntry {
                bytes,
                since: Instant::now(),
            });
        self.total += bytes;
    }

    fn sub(&mut self, seq: u64, bytes: u64) {
        if let Some(e) = self.by_seq.get_mut(&seq) {
            e.bytes -= bytes;
            if e.bytes == 0 {
                self.by_seq.remove(&seq);
            }
        }
        self.total -= bytes;
    }

    fn min_seq(&self) -> Option<u64> {
        self.by_seq.keys().next().copied()
    }
}

#[derive(Debug, Default)]
struct FileDirty {
    /// offset → interval; the intervals never overlap.
    map: BTreeMap<u64, Interval>,
    ledger: SeqLedger,
}

/// Per-file interval map of "dirty" ranges (later-wins).
#[derive(Debug, Default)]
pub struct DirtyIndex {
    files: HashMap<PathId, FileDirty>,
    ledger: SeqLedger,
}

fn end_of(start: u64, iv: &Interval) -> u64 {
    start + iv.len as u64
}

impl DirtyIndex {
    /// Record `[offset, offset+len)` of `file` as dirty; it replaces whatever overlaps it
    /// (later-wins: old intervals are trimmed or split).
    pub fn insert(
        &mut self,
        file: PathId,
        offset: u64,
        len: u32,
        loc: Loc,
    ) -> Result<(), RangeOverflow> {
        let end = offset.checked_add(len as u64).ok_or(RangeOverflow)?;
        if len == 0 {
            return Ok(());
        }
        self.remove_range(file, offset, end, |_| true);
        let fd = self.files.entry(file).or_default();
        fd.map.insert(offset, Interval { len, loc });
        fd.ledger.add(loc.seq.0, len as u64);
        self.ledger.add(loc.seq.0, len as u64);
        Ok(())
    }

    /// Remove the parts of the intervals that overlap `[start, end)` and satisfy `pred`;
    /// the remainders stay. Returns the number of bytes removed.
    fn remove_range(
        &mut self,
        file: PathId,
        start: u64,
        end: u64,
        pred: impl Fn(&Interval) -> bool,
    ) -> u64 {
        let Some(fd) = self.files.get_mut(&file) else {
            return 0;
        };
        if start >= end {
            return 0;
        }
        let mut hits: Vec<(u64, Interval)> = Vec::new();
        if let Some((&s, iv)) = fd.map.range(..start).next_back()
            && end_of(s, iv) > start
        {
            hits.push((s, *iv));
        }
        hits.extend(fd.map.range(start..end).map(|(s, iv)| (*s, *iv)));
        let mut removed = 0;
        for (s, iv) in hits {
            if !pred(&iv) {
                continue;
            }
            let e = end_of(s, &iv);
            fd.map.remove(&s);
            if s < start {
                fd.map.insert(
                    s,
                    Interval {
                        len: (start - s) as u32,
                        loc: iv.loc,
                    },
                );
            }
            if e > end {
                let cut = end - s;
                fd.map.insert(
                    end,
                    Interval {
                        len: (e - end) as u32,
                        loc: Loc {
                            data_offset: iv.loc.data_offset + cut,
                            ..iv.loc
                        },
                    },
                );
            }
            let gone = e.min(end) - s.max(start);
            fd.ledger.sub(iv.loc.seq.0, gone);
            self.ledger.sub(iv.loc.seq.0, gone);
            removed += gone;
        }
        if fd.map.is_empty() {
            self.files.remove(&file);
        }
        removed
    }

    /// Coverage of `[offset, offset+len)`: dirty pieces (to be read from the WAL) and holes
    /// (to be read from the appliance), in offset order.
    pub fn lookup(&self, file: PathId, offset: u64, len: u64) -> Vec<Piece> {
        let end = offset.saturating_add(len);
        if offset >= end {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cursor = offset;
        if let Some(fd) = self.files.get(&file) {
            let left = fd
                .map
                .range(..offset)
                .next_back()
                .filter(|(s, iv)| end_of(**s, iv) > offset);
            for (&s, iv) in left.into_iter().chain(fd.map.range(offset..end)) {
                let a = s.max(cursor);
                let b = end_of(s, iv).min(end);
                if a > cursor {
                    out.push(Piece::Missing {
                        offset: cursor,
                        len: a - cursor,
                    });
                }
                out.push(Piece::Dirty {
                    offset: a,
                    len: (b - a) as u32,
                    loc: Loc {
                        data_offset: iv.loc.data_offset + (a - s),
                        ..iv.loc
                    },
                });
                cursor = b;
            }
        }
        if cursor < end {
            out.push(Piece::Missing {
                offset: cursor,
                len: end - cursor,
            });
        }
        out
    }

    /// All dirty intervals of the file in offset order.
    pub fn dirty_ranges(&self, file: PathId) -> Vec<(u64, u32, Loc)> {
        self.files
            .get(&file)
            .map(|fd| fd.map.iter().map(|(s, iv)| (*s, iv.len, iv.loc)).collect())
            .unwrap_or_default()
    }

    /// The parts of `[offset, offset+len)` written by record `seq` have reached the appliance.
    /// Parts overwritten by a newer record stay dirty.
    pub fn ack(&mut self, file: PathId, offset: u64, len: u32, seq: Seq) -> u64 {
        let end = offset.saturating_add(len as u64);
        self.remove_range(file, offset, end, |iv| iv.loc.seq == seq)
    }

    /// Forget the dirty bytes at or after `offset` (delete, truncate).
    pub fn drop_from(&mut self, file: PathId, offset: u64) -> u64 {
        self.remove_range(file, offset, u64::MAX, |_| true)
    }

    /// First contiguous run of dirty bytes (at most `max_bytes`) that does not overlap any of
    /// the `skip` ranges (`(start, end)`; ranges being uploaded right now). The last interval
    /// may be cut at the limit.
    pub fn run(&self, file: PathId, skip: &[(u64, u64)], max_bytes: u64) -> Vec<(u64, u32, Loc)> {
        let mut out: Vec<(u64, u32, Loc)> = Vec::new();
        let Some(fd) = self.files.get(&file) else {
            return out;
        };
        let (mut total, mut run_end) = (0u64, 0u64);
        for (&s, iv) in &fd.map {
            let e = end_of(s, iv);
            if skip.iter().any(|&(a, b)| s < b && a < e) {
                if out.is_empty() {
                    continue;
                }
                break;
            }
            if !out.is_empty() && s != run_end {
                break;
            }
            let take = (iv.len as u64).min(max_bytes - total);
            out.push((s, take as u32, iv.loc));
            total += take;
            run_end = s + take;
            if total >= max_bytes {
                break;
            }
        }
        out
    }

    /// End of the last dirty byte of the file.
    pub fn dirty_end(&self, file: PathId) -> Option<u64> {
        self.files
            .get(&file)
            .and_then(|fd| fd.map.iter().next_back())
            .map(|(s, iv)| end_of(*s, iv))
    }

    pub fn has_dirty(&self, file: PathId) -> bool {
        self.files.contains_key(&file)
    }

    /// Lowest seq among the live bytes of the file.
    pub fn file_min_seq(&self, file: PathId) -> Option<Seq> {
        self.files
            .get(&file)
            .and_then(|fd| fd.ledger.min_seq())
            .map(Seq)
    }

    pub fn file_bytes(&self, file: PathId) -> u64 {
        self.files.get(&file).map_or(0, |fd| fd.ledger.total)
    }

    /// Files with dirty bytes, the one holding the oldest record first.
    pub fn dirty_files_by_age(&self) -> Vec<PathId> {
        let mut v: Vec<(u64, PathId)> = self
            .files
            .iter()
            .filter_map(|(f, fd)| fd.ledger.min_seq().map(|s| (s, *f)))
            .collect();
        v.sort();
        v.into_iter().map(|(_, f)| f).collect()
    }

    pub fn dirty_file_count(&self) -> usize {
        self.files.len()
    }

    pub fn live_bytes(&self) -> u64 {
        self.ledger.total
    }

    pub fn min_live_seq(&self) -> Option<Seq> {
        self.ledger.min_seq().map(Seq)
    }

    /// When the oldest live record was written (or recovered).
    pub fn oldest_since(&self) -> Option<Instant> {
        self.ledger.by_seq.values().next().map(|e| e.since)
    }
}

// ---- the journal --------------------------------------------------------------------------

/// Persistence of the durable state of smb-core handles (create_guid, path, lease).
/// J4; not implemented in J3b.
#[derive(Debug, Default)]
pub struct ParkedHandleStore;

#[derive(Debug, Clone)]
pub struct JournalOptions {
    /// Segment size; a record larger than this gets a segment of its own.
    pub segment_size: u64,
    /// fsync of the watermark file too (LOCAL_JOURNAL). Segments are synced on rollover and by
    /// `sync()` either way; without `sync()` a power loss can lose the tail, a process kill
    /// cannot.
    pub durable: bool,
    /// Ask Time Machine to skip the directory (macOS, best effort).
    pub exclude_from_backups: bool,
}

impl Default for JournalOptions {
    fn default() -> Self {
        JournalOptions {
            segment_size: SEGMENT_SIZE,
            durable: false,
            exclude_from_backups: false,
        }
    }
}

/// What `Journal::open` found on disk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub watermark: u64,
    pub segments_found: usize,
    pub segments_removed: usize,
    pub records: u64,
    /// Write records replayed into the index (seq above the watermark).
    pub replayed_records: u64,
    pub replayed_bytes: u64,
    /// Bytes cut off the end of the last segment (a torn write).
    pub dropped_tail_bytes: u64,
    /// Segments that were NOT last yet had an invalid record: bit rot, not a crash. The rest
    /// of such a segment is ignored (data loss).
    pub corrupt_segments: Vec<u32>,
}

#[derive(Debug)]
struct Segment {
    reader: File,
    writer: Option<File>,
    len: u64,
    last_seq: u64,
}

#[derive(Debug, Default)]
struct PathTable {
    by_name: HashMap<String, PathId>,
    by_id: HashMap<PathId, String>,
    next: u32,
}

impl PathTable {
    fn intern(&mut self, name: &str) -> PathId {
        if let Some(id) = self.by_name.get(name) {
            return *id;
        }
        let id = PathId(self.next);
        self.next += 1;
        self.define(id, name);
        id
    }

    fn define(&mut self, id: PathId, name: &str) {
        self.by_name.insert(name.to_owned(), id);
        self.by_id.insert(id, name.to_owned());
        self.next = self.next.max(id.0 + 1);
    }
}

#[derive(Debug)]
struct Inner {
    index: DirtyIndex,
    paths: PathTable,
    segments: BTreeMap<u32, Segment>,
    active: Option<u32>,
    next_seq: u64,
    persisted_watermark: u64,
    disk_bytes: u64,
    /// Files whose `Path` record is already in the active segment.
    defs_in_active: HashSet<PathId>,
    /// Newest write record per file. A restart replays records above the persisted watermark,
    /// including ones the appliance already has; a file that was deleted, renamed or truncated
    /// since must not be rewritten by such a replay, so it gets a `Drop` record.
    last_write: HashMap<PathId, u64>,
}

/// Journal: append-only segments (~64 MB) + an index.
#[derive(Debug)]
pub struct Journal {
    dir: PathBuf,
    opts: JournalOptions,
    inner: Mutex<Inner>,
}

/// One WriteRange worth of dirty data, read out of the journal.
#[derive(Debug)]
pub struct Batch {
    pub file: PathId,
    pub path: String,
    pub offset: u64,
    pub data: Vec<u8>,
    /// The records (sub-ranges) the data was assembled from; acknowledge each with `Journal::ack`.
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part {
    pub offset: u64,
    pub len: u32,
    pub seq: Seq,
}

fn overflow() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "write range exceeds u64")
}

impl Inner {
    fn watermark(&self) -> u64 {
        match self.index.min_live_seq() {
            Some(Seq(s)) => s - 1,
            None => self.next_seq - 1,
        }
    }

    fn start_segment(&mut self, dir: &Path) -> io::Result<u32> {
        let id = self.segments.keys().next_back().map_or(1, |k| k + 1);
        let path = dir.join(segment_name(id));
        let mut w = private_file_opts()
            .append(true)
            .create_new(true)
            .open(&path)?;
        w.write_all(&segment_header())?;
        let reader = File::open(&path)?;
        self.segments.insert(
            id,
            Segment {
                reader,
                writer: Some(w),
                len: SEG_HEADER_LEN,
                last_seq: 0,
            },
        );
        self.disk_bytes += SEG_HEADER_LEN;
        self.active = Some(id);
        self.defs_in_active.clear();
        Ok(id)
    }

    /// The active segment, rolled over if `need` more bytes do not fit.
    fn active_for(&mut self, need: u64, opts: &JournalOptions, dir: &Path) -> io::Result<u32> {
        if let Some(id) = self.active {
            let seg = &self.segments[&id];
            if seg.len + need <= opts.segment_size || seg.len == SEG_HEADER_LEN {
                return Ok(id);
            }
            // A finished segment is always synced, so that `sync()` of the active one makes
            // everything written so far durable (LOCAL_JOURNAL).
            if let Some(w) = &seg.writer {
                w.sync_data()?;
            }
            self.segments.get_mut(&id).expect("active").writer = None;
            self.active = None;
        }
        self.start_segment(dir)
    }

    /// Write one record into the ACTIVE segment (the caller made room with `active_for`);
    /// returns the segment and the file offset of the payload.
    fn write_raw(&mut self, h: &RecordHeader, payload: &[u8]) -> io::Result<(u32, u64)> {
        let id = self.active.expect("active_for was called");
        let need = (REC_HEADER_LEN + payload.len()) as u64;
        let seg = self.segments.get_mut(&id).expect("active");
        let before = seg.len;
        let w = seg.writer.as_mut().expect("active segment has a writer");
        let r = w.write_all(&h.encode()).and_then(|_| w.write_all(payload));
        if let Err(e) = r {
            // Cut the torn record so the next append starts clean (best effort).
            let _ = w.set_len(before);
            return Err(e);
        }
        seg.len += need;
        seg.last_seq = seg.last_seq.max(h.seq.0);
        self.disk_bytes += need;
        Ok((id, before + REC_HEADER_LEN as u64))
    }

    /// Make room for a record of `payload` bytes about `file`, with its `Path` record if the
    /// active segment does not have one yet, and write the `Path` record. After this the
    /// caller writes its record with `write_raw` (no roll can happen in between).
    fn prepare(
        &mut self,
        opts: &JournalOptions,
        dir: &Path,
        file: PathId,
        payload: usize,
    ) -> io::Result<()> {
        let name = self
            .paths
            .by_id
            .get(&file)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown PathId"))?;
        let need = (2 * REC_HEADER_LEN + name.len() + payload) as u64;
        self.active_for(need, opts, dir)?;
        if !self.defs_in_active.contains(&file) {
            let h = RecordHeader {
                kind: KIND_PATH,
                seq: Seq(0),
                file,
                offset: 0,
                len: name.len() as u32,
                data_crc: crc32fast::hash(name.as_bytes()),
            };
            self.write_raw(&h, name.as_bytes())?;
            self.defs_in_active.insert(file);
        }
        Ok(())
    }

    fn persist_watermark(&mut self, dir: &Path, durable: bool) -> io::Result<u64> {
        let w = self.watermark();
        if w > self.persisted_watermark {
            write_watermark(dir, w, durable)?;
            self.persisted_watermark = w;
        }
        Ok(w)
    }
}

fn write_watermark(dir: &Path, w: u64, durable: bool) -> io::Result<()> {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(WATERMARK_MAGIC);
    body.extend_from_slice(&w.to_le_bytes());
    let crc = crc32fast::hash(&body);
    body.extend_from_slice(&crc.to_le_bytes());
    write_atomic(&dir.join(WATERMARK_FILE), &body, durable)
}

/// `None` = absent or damaged (the journal is then replayed in full, which is safe).
fn read_watermark(dir: &Path) -> Option<u64> {
    let b = std::fs::read(dir.join(WATERMARK_FILE)).ok()?;
    if b.len() != 20 || &b[..8] != WATERMARK_MAGIC {
        return None;
    }
    let crc = u32::from_le_bytes(b[16..20].try_into().ok()?);
    if crc32fast::hash(&b[..16]) != crc {
        return None;
    }
    Some(u64::from_le_bytes(b[8..16].try_into().ok()?))
}

/// Result of scanning one segment.
struct Scan {
    /// End of the last valid record.
    good_end: u64,
    /// The whole file was consumed without finding an invalid record.
    clean: bool,
    last_seq: u64,
}

fn scan_segment(
    path: &Path,
    id: u32,
    watermark: u64,
    paths: &mut PathTable,
    index: &mut DirtyIndex,
    last_write: &mut HashMap<PathId, u64>,
    report: &mut RecoveryReport,
) -> io::Result<Scan> {
    let f = File::open(path)?;
    let file_len = f.metadata()?.len();
    let mut r = BufReader::with_capacity(1 << 20, f);
    let mut scan = Scan {
        good_end: 0,
        clean: false,
        last_seq: 0,
    };
    let mut hdr = [0u8; SEG_HEADER_LEN as usize];
    if file_len < SEG_HEADER_LEN || r.read_exact(&mut hdr).is_err() || hdr != segment_header() {
        return Ok(scan);
    }
    let mut pos = SEG_HEADER_LEN;
    scan.good_end = pos;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if pos == file_len {
            scan.clean = true;
            return Ok(scan);
        }
        if file_len - pos < REC_HEADER_LEN as u64 {
            return Ok(scan);
        }
        let mut hb = [0u8; REC_HEADER_LEN];
        r.read_exact(&mut hb)?;
        let Some(h) = RecordHeader::decode(&hb) else {
            return Ok(scan);
        };
        let payload_pos = pos + REC_HEADER_LEN as u64;
        let end = payload_pos + h.len as u64;
        if end > file_len {
            return Ok(scan);
        }
        let skip_payload = h.kind == KIND_WRITE && h.seq.0 <= watermark;
        if skip_payload {
            // Already on the appliance: only the position matters, not the bytes.
            r.seek_relative(h.len as i64)?;
        } else {
            buf.resize(h.len as usize, 0);
            r.read_exact(&mut buf)?;
            if crc32fast::hash(&buf) != h.data_crc {
                return Ok(scan);
            }
        }
        match h.kind {
            KIND_PATH => match std::str::from_utf8(&buf) {
                Ok(name) => paths.define(h.file, name),
                Err(_) => return Ok(scan),
            },
            KIND_WRITE if h.seq.0 > watermark => {
                if !paths.by_id.contains_key(&h.file)
                    || index
                        .insert(
                            h.file,
                            h.offset,
                            h.len,
                            Loc {
                                segment: id,
                                data_offset: payload_pos,
                                seq: h.seq,
                            },
                        )
                        .is_err()
                {
                    return Ok(scan);
                }
                last_write.insert(h.file, h.seq.0);
                report.replayed_records += 1;
                report.replayed_bytes += h.len as u64;
            }
            KIND_DROP if h.seq.0 > watermark => {
                index.drop_from(h.file, h.offset);
            }
            _ => {}
        }
        report.records += 1;
        scan.last_seq = scan.last_seq.max(h.seq.0);
        pos = end;
        scan.good_end = pos;
    }
}

impl Journal {
    /// Recovery at startup: scan segments, verify CRCs, cut a torn tail, rebuild the
    /// `DirtyIndex` from the records the appliance has not acknowledged (above the stored
    /// watermark). New records continue in a fresh segment.
    pub fn open(dir: &Path, opts: JournalOptions) -> io::Result<(Journal, RecoveryReport)> {
        let fresh = !dir.exists();
        open_private_dir(dir)?;
        if fresh && opts.exclude_from_backups {
            exclude_from_backups(dir);
        }
        let watermark = read_watermark(dir).unwrap_or(0);
        let mut report = RecoveryReport {
            watermark,
            ..Default::default()
        };

        let mut ids: Vec<u32> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| parse_segment_name(&e.file_name().to_string_lossy()))
            .collect();
        ids.sort_unstable();
        report.segments_found = ids.len();

        let mut paths = PathTable::default();
        let mut index = DirtyIndex::default();
        let mut last_write: HashMap<PathId, u64> = HashMap::new();
        let mut segments: BTreeMap<u32, Segment> = BTreeMap::new();
        let mut max_seq = watermark;
        let mut disk_bytes = 0;
        for (n, &id) in ids.iter().enumerate() {
            let path = dir.join(segment_name(id));
            let is_last = n + 1 == ids.len();
            let scan = scan_segment(
                &path,
                id,
                watermark,
                &mut paths,
                &mut index,
                &mut last_write,
                &mut report,
            )?;
            let file_len = std::fs::metadata(&path)?.len();
            if !scan.clean {
                if is_last {
                    report.dropped_tail_bytes += file_len - scan.good_end;
                    if scan.good_end < SEG_HEADER_LEN {
                        // Not even a valid header (a crash right after creation).
                        std::fs::remove_file(&path)?;
                        continue;
                    }
                    let f = OpenOptions::new().write(true).open(&path)?;
                    f.set_len(scan.good_end)?;
                } else {
                    report.corrupt_segments.push(id);
                }
            }
            max_seq = max_seq.max(scan.last_seq);
            let len = if !scan.clean && is_last {
                scan.good_end
            } else {
                file_len
            };
            disk_bytes += len;
            segments.insert(
                id,
                Segment {
                    reader: File::open(&path)?,
                    writer: None,
                    len,
                    last_seq: scan.last_seq,
                },
            );
        }

        let mut inner = Inner {
            index,
            paths,
            segments,
            active: None,
            next_seq: max_seq + 1,
            persisted_watermark: watermark,
            disk_bytes,
            defs_in_active: HashSet::new(),
            last_write,
        };
        // Segments the stored watermark already covers are garbage.
        let stale: Vec<u32> = inner
            .segments
            .iter()
            .filter(|(_, s)| s.last_seq <= watermark)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(s) = inner.segments.remove(&id) {
                inner.disk_bytes -= s.len;
                drop(s);
                let _ = std::fs::remove_file(dir.join(segment_name(id)));
                report.segments_removed += 1;
            }
        }
        Ok((
            Journal {
                dir: dir.to_owned(),
                opts,
                inner: Mutex::new(inner),
            },
            report,
        ))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("journal poisoned")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The id of a path, creating it if needed (needed to write).
    pub fn intern(&self, path: &str) -> PathId {
        self.lock().paths.intern(path)
    }

    /// The id of a path that was written at some point; `None` = never, so it has no dirty data.
    pub fn file_id(&self, path: &str) -> Option<PathId> {
        self.lock().paths.by_name.get(path).copied()
    }

    pub fn path_of(&self, file: PathId) -> Option<String> {
        self.lock().paths.by_id.get(&file).cloned()
    }

    /// Append a write: the record goes to the active segment, the index is updated (later-wins).
    pub fn append(&self, file: PathId, offset: u64, data: &[u8]) -> io::Result<Seq> {
        if data.is_empty() {
            return Ok(Seq(self.lock().next_seq - 1));
        }
        if offset.checked_add(data.len() as u64).is_none() || data.len() > u32::MAX as usize {
            return Err(overflow());
        }
        let data_crc = crc32fast::hash(data);
        let mut g = self.lock();
        g.prepare(&self.opts, &self.dir, file, data.len())?;
        let seq = Seq(g.next_seq);
        let h = RecordHeader {
            kind: KIND_WRITE,
            seq,
            file,
            offset,
            len: data.len() as u32,
            data_crc,
        };
        let (segment, data_offset) = g.write_raw(&h, data)?;
        g.next_seq += 1;
        g.last_write.insert(file, seq.0);
        g.index
            .insert(
                file,
                offset,
                data.len() as u32,
                Loc {
                    segment,
                    data_offset,
                    seq,
                },
            )
            .map_err(|_| overflow())?;
        Ok(seq)
    }

    /// The file is deleted, renamed away or truncated to `offset`: discard its dirty bytes at
    /// or after `offset`. Durable as a record (written whenever the file has dirty bytes or
    /// records a restart could replay), so a restart does not bring them back.
    pub fn drop_from(&self, file: PathId, offset: u64) -> io::Result<u64> {
        let mut g = self.lock();
        Self::drop_locked(&mut g, &self.opts, &self.dir, file, offset)
    }

    fn drop_locked(
        g: &mut Inner,
        opts: &JournalOptions,
        dir: &Path,
        file: PathId,
        offset: u64,
    ) -> io::Result<u64> {
        let replayable = g
            .last_write
            .get(&file)
            .is_some_and(|s| *s > g.persisted_watermark);
        if !g.index.has_dirty(file) && !replayable {
            return Ok(0);
        }
        g.prepare(opts, dir, file, 0)?;
        let seq = Seq(g.next_seq);
        let h = RecordHeader {
            kind: KIND_DROP,
            seq,
            file,
            offset,
            len: 0,
            data_crc: crc32fast::hash(&[]),
        };
        g.write_raw(&h, &[])?;
        g.next_seq += 1;
        if offset == 0 {
            g.last_write.remove(&file);
        }
        Ok(g.index.drop_from(file, offset))
    }

    /// `drop_from(.., 0)` for every file at or below `prefix` (a renamed or deleted directory).
    pub fn forget_under(&self, prefix: &str) -> io::Result<()> {
        let mut g = self.lock();
        let files: Vec<PathId> = g
            .paths
            .by_id
            .iter()
            .filter(|(_, p)| {
                prefix.is_empty()
                    || *p == prefix
                    || p.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'))
            })
            .map(|(f, _)| *f)
            .collect();
        for f in files {
            Self::drop_locked(&mut g, &self.opts, &self.dir, f, 0)?;
        }
        Ok(())
    }

    fn read_pieces(g: &Inner, pieces: &[Piece]) -> io::Result<Vec<Chunk>> {
        let mut out = Vec::with_capacity(pieces.len());
        for p in pieces {
            out.push(match *p {
                Piece::Missing { offset, len } => Chunk::Missing { offset, len },
                Piece::Dirty { offset, len, loc } => Chunk::Wal {
                    offset,
                    data: Self::read_loc_locked(g, loc, len)?,
                },
            });
        }
        Ok(out)
    }

    fn read_loc_locked(g: &Inner, loc: Loc, len: u32) -> io::Result<Vec<u8>> {
        let seg = g
            .segments
            .get(&loc.segment)
            .ok_or_else(|| io::Error::other("journal segment is gone"))?;
        let mut buf = vec![0u8; len as usize];
        read_exact_at(&seg.reader, &mut buf, loc.data_offset)?;
        Ok(buf)
    }

    /// Read-your-writes: WAL pieces + holes to read through from the appliance.
    pub fn read_overlay(&self, file: PathId, offset: u64, len: u64) -> io::Result<Vec<Chunk>> {
        let g = self.lock();
        let pieces = g.index.lookup(file, offset, len);
        Self::read_pieces(&g, &pieces)
    }

    /// The next WriteRange for `file`: a contiguous run of dirty bytes (at most `max_bytes`)
    /// that does not overlap `skip`.
    pub fn plan_batch(
        &self,
        file: PathId,
        skip: &[(u64, u64)],
        max_bytes: usize,
    ) -> io::Result<Option<Batch>> {
        let g = self.lock();
        let run = g.index.run(file, skip, max_bytes as u64);
        let Some(&(offset, _, _)) = run.first() else {
            return Ok(None);
        };
        let Some(path) = g.paths.by_id.get(&file).cloned() else {
            return Ok(None);
        };
        let mut data = Vec::with_capacity(run.iter().map(|r| r.1 as usize).sum());
        let mut parts = Vec::with_capacity(run.len());
        for (off, len, loc) in run {
            data.extend_from_slice(&Self::read_loc_locked(&g, loc, len)?);
            parts.push(Part {
                offset: off,
                len,
                seq: loc.seq,
            });
        }
        Ok(Some(Batch {
            file,
            path,
            offset,
            data,
            parts,
        }))
    }

    /// The appliance acknowledged the part: it is no longer dirty (unless overwritten since).
    pub fn ack(&self, file: PathId, part: Part) -> u64 {
        self.lock().index.ack(file, part.offset, part.len, part.seq)
    }

    /// All seq ≤ the returned watermark are acknowledged (or superseded).
    pub fn watermark(&self) -> Seq {
        Seq(self.lock().watermark())
    }

    /// Persist the watermark (if it moved) and delete the segments it fully covers. An idle
    /// active segment that is entirely acknowledged is closed first so it can go too.
    pub fn trim(&self) -> io::Result<usize> {
        let mut g = self.lock();
        let w = g.persist_watermark(&self.dir, self.opts.durable)?;
        if g.index.live_bytes() == 0
            && let Some(id) = g.active
            && g.segments[&id].len > SEG_HEADER_LEN
        {
            g.segments.get_mut(&id).expect("active").writer = None;
            g.active = None;
        }
        let stale: Vec<u32> = g
            .segments
            .iter()
            .filter(|(id, s)| Some(**id) != g.active && s.last_seq <= w)
            .map(|(id, _)| *id)
            .collect();
        let n = stale.len();
        for id in stale {
            if let Some(s) = g.segments.remove(&id) {
                g.disk_bytes -= s.len;
                drop(s);
                let _ = std::fs::remove_file(self.dir.join(segment_name(id)));
            }
        }
        Ok(n)
    }

    /// Persist the watermark so that a restart cannot replay records older than it. Call before
    /// changing receiver state (delete / rename / truncate) of files that were written.
    pub fn persist_watermark(&self) -> io::Result<Seq> {
        let mut g = self.lock();
        g.persist_watermark(&self.dir, self.opts.durable).map(Seq)
    }

    /// fsync of the active segment (LOCAL_JOURNAL).
    pub fn sync(&self) -> io::Result<()> {
        let g = self.lock();
        if let Some(id) = g.active
            && let Some(w) = &g.segments[&id].writer
        {
            w.sync_data()?;
        }
        Ok(())
    }

    // ---- queries (all cheap) ----

    pub fn live_bytes(&self) -> u64 {
        self.lock().index.live_bytes()
    }

    pub fn disk_bytes(&self) -> u64 {
        self.lock().disk_bytes
    }

    pub fn last_seq(&self) -> Seq {
        Seq(self.lock().next_seq - 1)
    }

    pub fn segment_count(&self) -> usize {
        self.lock().segments.len()
    }

    /// Age of the oldest record that has not reached the appliance.
    pub fn oldest_age(&self) -> Option<Duration> {
        self.lock().index.oldest_since().map(|t| t.elapsed())
    }

    pub fn dirty_end(&self, file: PathId) -> Option<u64> {
        self.lock().index.dirty_end(file)
    }

    pub fn has_dirty(&self, file: PathId) -> bool {
        self.lock().index.has_dirty(file)
    }

    /// Seq of the newest write record of the file in this run or the replayed journal.
    pub fn last_write_seq(&self, file: PathId) -> Option<Seq> {
        self.lock().last_write.get(&file).copied().map(Seq)
    }

    pub fn has_any_dirty(&self) -> bool {
        self.lock().index.dirty_file_count() > 0
    }

    pub fn file_min_seq(&self, file: PathId) -> Option<Seq> {
        self.lock().index.file_min_seq(file)
    }

    pub fn dirty_files_by_age(&self) -> Vec<PathId> {
        self.lock().index.dirty_files_by_age()
    }

    /// Files with dirty bytes whose path is `prefix` or below it.
    pub fn dirty_files_under(&self, prefix: &str) -> Vec<PathId> {
        let g = self.lock();
        g.index
            .dirty_files_by_age()
            .into_iter()
            .filter(|f| {
                g.paths.by_id.get(f).is_some_and(|p| {
                    prefix.is_empty()
                        || p == prefix
                        || p.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'))
                })
            })
            .collect()
    }

    /// Dirty end of every dirty file under the (possibly empty = root) directory, by path:
    /// lets a listing show sizes that include unuploaded data.
    pub fn dirty_ends_in(&self, dir: &str) -> HashMap<String, u64> {
        let g = self.lock();
        let mut out = HashMap::new();
        for f in g.index.dirty_files_by_age() {
            let Some(p) = g.paths.by_id.get(&f) else {
                continue;
            };
            let parent = p.rsplit_once('/').map_or("", |(d, _)| d);
            if parent == dir
                && let Some(e) = g.index.dirty_end(f)
            {
                out.insert(p.clone(), e);
            }
        }
        out
    }
}

/// Ask Time Machine to skip `dir` (a backup of the backup journal is circular). Best effort,
/// and off the caller's thread: `tmutil` can take many seconds.
fn exclude_from_backups(dir: &Path) {
    #[cfg(target_os = "macos")]
    {
        let dir = dir.to_owned();
        std::thread::spawn(move || {
            let _ = std::process::Command::new("tmutil")
                .arg("addexclusion")
                .arg(dir)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        });
    }
    #[cfg(not(target_os = "macos"))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: PathId = PathId(1);

    fn loc(seq: u64, data_offset: u64) -> Loc {
        Loc {
            segment: 1,
            data_offset,
            seq: Seq(seq),
        }
    }

    // ---- DirtyIndex vs a naive byte model ----

    /// xorshift: a self-made generator keeps the property test dependency-free and replayable.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// For every byte: `(seq, data_offset of that byte)` of the record that owns it.
    #[derive(Clone)]
    struct Model(Vec<Option<(u64, u64)>>);

    impl Model {
        fn insert(&mut self, off: u64, len: u64, seq: u64, base: u64) {
            for i in 0..len {
                self.0[(off + i) as usize] = Some((seq, base + i));
            }
        }
        fn ack(&mut self, off: u64, len: u64, seq: u64) {
            for i in off..off + len {
                if self.0[i as usize].is_some_and(|(s, _)| s == seq) {
                    self.0[i as usize] = None;
                }
            }
        }
        fn drop_from(&mut self, off: u64) {
            for i in off as usize..self.0.len() {
                self.0[i] = None;
            }
        }
        fn live(&self) -> u64 {
            self.0.iter().filter(|b| b.is_some()).count() as u64
        }
        fn min_seq(&self) -> Option<u64> {
            self.0.iter().flatten().map(|(s, _)| *s).min()
        }
    }

    fn check_equivalent(idx: &DirtyIndex, m: &Model, rng: &mut Rng) {
        let n = m.0.len() as u64;
        assert_eq!(idx.live_bytes(), m.live());
        assert_eq!(idx.min_live_seq().map(|s| s.0), m.min_seq());
        // the intervals never overlap or touch zero length
        let mut prev_end = 0;
        for (s, len, _) in idx.dirty_ranges(F) {
            assert!(len > 0 && s >= prev_end);
            prev_end = s + len as u64;
        }
        for _ in 0..8 {
            let off = rng.below(n + 8);
            let len = rng.below(n + 8);
            let mut seen = vec![false; (n + 16) as usize];
            let mut cursor = off;
            for p in idx.lookup(F, off, len) {
                match p {
                    Piece::Dirty { offset, len, loc } => {
                        assert_eq!(offset, cursor, "pieces are contiguous and ordered");
                        for i in 0..len as u64 {
                            let want = m.0.get((offset + i) as usize).copied().flatten();
                            assert_eq!(
                                want,
                                Some((loc.seq.0, loc.data_offset + i)),
                                "byte {}",
                                offset + i
                            );
                            seen[(offset + i) as usize] = true;
                        }
                        cursor += len as u64;
                    }
                    Piece::Missing { offset, len } => {
                        assert_eq!(offset, cursor);
                        for i in 0..len {
                            assert!(
                                m.0.get((offset + i) as usize).copied().flatten().is_none(),
                                "byte {} should be a hole",
                                offset + i
                            );
                        }
                        cursor += len;
                    }
                }
            }
            if len > 0 {
                assert_eq!(cursor, off + len);
            }
        }
    }

    #[test]
    fn index_is_equivalent_to_the_naive_model_on_random_operations() {
        for seed in 1..=40u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let n = 200u64;
            let mut idx = DirtyIndex::default();
            let mut m = Model(vec![None; n as usize]);
            for seq in 1..=120u64 {
                match rng.below(10) {
                    0..=6 => {
                        let off = rng.below(n);
                        let len = 1 + rng.below((n - off).min(60));
                        let base = seq * 10_000;
                        idx.insert(F, off, len as u32, loc(seq, base)).unwrap();
                        m.insert(off, len, seq, base);
                    }
                    7 | 8 => {
                        // acknowledge a random live interval, as the uploader does
                        let ranges = idx.dirty_ranges(F);
                        if !ranges.is_empty() {
                            let (s, len, l) = ranges[rng.below(ranges.len() as u64) as usize];
                            idx.ack(F, s, len, l.seq);
                            m.ack(s, len as u64, l.seq.0);
                        }
                    }
                    _ => {
                        let off = rng.below(n);
                        idx.drop_from(F, off);
                        m.drop_from(off);
                    }
                }
                check_equivalent(&idx, &m, &mut rng);
            }
        }
    }

    #[test]
    fn insert_splits_old_intervals_later_wins() {
        let mut idx = DirtyIndex::default();
        idx.insert(F, 0, 100, loc(1, 1000)).unwrap();
        idx.insert(F, 40, 20, loc(2, 5000)).unwrap();
        assert_eq!(
            idx.dirty_ranges(F),
            vec![
                (0, 40, loc(1, 1000)),
                (40, 20, loc(2, 5000)),
                (60, 40, loc(1, 1060)),
            ]
        );
        // overlapping from both sides and covering several
        idx.insert(F, 30, 50, loc(3, 9000)).unwrap();
        assert_eq!(
            idx.dirty_ranges(F),
            vec![
                (0, 30, loc(1, 1000)),
                (30, 50, loc(3, 9000)),
                (80, 20, loc(1, 1080)),
            ]
        );
        // an exact overwrite replaces, a covered one disappears
        idx.insert(F, 30, 50, loc(4, 100)).unwrap();
        assert_eq!(idx.dirty_ranges(F)[1], (30, 50, loc(4, 100)));
        assert!(idx.min_live_seq() == Some(Seq(1)));
        assert_eq!(idx.live_bytes(), 100);
    }

    #[test]
    fn lookup_reports_hole_and_dirty_pieces() {
        let mut idx = DirtyIndex::default();
        idx.insert(F, 10, 10, loc(1, 100)).unwrap();
        idx.insert(F, 30, 10, loc(2, 200)).unwrap();
        assert_eq!(
            idx.lookup(F, 5, 40),
            vec![
                Piece::Missing { offset: 5, len: 5 },
                Piece::Dirty {
                    offset: 10,
                    len: 10,
                    loc: loc(1, 100)
                },
                Piece::Missing {
                    offset: 20,
                    len: 10
                },
                Piece::Dirty {
                    offset: 30,
                    len: 10,
                    loc: loc(2, 200)
                },
                Piece::Missing { offset: 40, len: 5 },
            ]
        );
        // the window starts inside an interval
        assert_eq!(
            idx.lookup(F, 15, 3),
            vec![Piece::Dirty {
                offset: 15,
                len: 3,
                loc: loc(1, 105)
            }]
        );
        assert!(idx.lookup(F, 15, 0).is_empty());
        assert_eq!(
            idx.lookup(PathId(9), 0, 4),
            vec![Piece::Missing { offset: 0, len: 4 }]
        );
    }

    #[test]
    fn index_boundaries_at_u64_max() {
        let mut idx = DirtyIndex::default();
        // zero length: nothing happens
        idx.insert(F, 5, 0, loc(1, 0)).unwrap();
        assert_eq!(idx.live_bytes(), 0);
        assert!(!idx.has_dirty(F));
        // the last addressable bytes
        idx.insert(F, u64::MAX - 10, 10, loc(1, 0)).unwrap();
        assert_eq!(idx.dirty_end(F), Some(u64::MAX));
        // one byte too far
        assert_eq!(
            idx.insert(F, u64::MAX - 9, 10, loc(2, 0)),
            Err(RangeOverflow)
        );
        assert_eq!(idx.live_bytes(), 10);
        // lookups never wrap
        let p = idx.lookup(F, u64::MAX - 20, u64::MAX);
        assert_eq!(
            p,
            vec![
                Piece::Missing {
                    offset: u64::MAX - 20,
                    len: 10
                },
                Piece::Dirty {
                    offset: u64::MAX - 10,
                    len: 10,
                    loc: loc(1, 0)
                },
            ]
        );
        assert!(idx.lookup(F, u64::MAX, 5).is_empty());
        assert_eq!(idx.drop_from(F, u64::MAX - 5), 5);
        assert_eq!(idx.ack(F, u64::MAX - 10, 5, Seq(1)), 5);
        assert!(!idx.has_dirty(F));
    }

    #[test]
    fn ack_leaves_overwritten_parts_dirty() {
        let mut idx = DirtyIndex::default();
        idx.insert(F, 0, 100, loc(1, 0)).unwrap();
        idx.insert(F, 50, 10, loc(2, 500)).unwrap();
        // the uploader had planned [0,100) of record 1
        assert_eq!(idx.ack(F, 0, 100, Seq(1)), 90);
        assert_eq!(idx.dirty_ranges(F), vec![(50, 10, loc(2, 500))]);
        assert_eq!(idx.min_live_seq(), Some(Seq(2)));
    }

    #[test]
    fn run_skips_inflight_and_stops_at_gaps_and_limit() {
        let mut idx = DirtyIndex::default();
        idx.insert(F, 0, 10, loc(1, 0)).unwrap();
        idx.insert(F, 10, 10, loc(2, 100)).unwrap();
        idx.insert(F, 20, 10, loc(3, 200)).unwrap();
        idx.insert(F, 40, 10, loc(4, 300)).unwrap();
        let r = idx.run(F, &[], 1000);
        assert_eq!(
            r.iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(),
            [(0, 10), (10, 10), (20, 10)]
        );
        let r = idx.run(F, &[(0, 10)], 1000);
        assert_eq!(r.iter().map(|x| x.0).collect::<Vec<_>>(), [10, 20]);
        let r = idx.run(F, &[], 15);
        assert_eq!(
            r.iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(),
            [(0, 10), (10, 5)]
        );
        // a skipped middle interval ends the run
        let r = idx.run(F, &[(10, 20)], 1000);
        assert_eq!(r.iter().map(|x| x.0).collect::<Vec<_>>(), [0]);
    }

    // ---- file format and recovery ----

    fn tmpdir(name: &str) -> PathBuf {
        let mut r = [0u8; 4];
        getrandom::fill(&mut r).unwrap();
        let d = std::env::temp_dir().join(format!(
            "janus-wal-{name}-{}-{}",
            std::process::id(),
            u32::from_le_bytes(r)
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn open(dir: &Path) -> (Journal, RecoveryReport) {
        Journal::open(dir, JournalOptions::default()).unwrap()
    }

    fn small(dir: &Path, size: u64) -> (Journal, RecoveryReport) {
        Journal::open(
            dir,
            JournalOptions {
                segment_size: size,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn overlay_bytes(j: &Journal, path: &str, len: u64) -> Vec<Option<u8>> {
        let mut out = vec![None; len as usize];
        let Some(f) = j.file_id(path) else {
            return out;
        };
        for c in j.read_overlay(f, 0, len).unwrap() {
            if let Chunk::Wal { offset, data } = c {
                for (i, b) in data.iter().enumerate() {
                    out[offset as usize + i] = Some(*b);
                }
            }
        }
        out
    }

    fn last_segment(dir: &Path) -> PathBuf {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "wal"))
            .collect();
        v.sort();
        v.pop().unwrap()
    }

    #[test]
    fn empty_journal_recovers_empty() {
        let d = tmpdir("empty");
        let (j, r) = open(&d);
        assert_eq!(r.records, 0);
        assert_eq!(j.live_bytes(), 0);
        assert_eq!(j.last_seq(), Seq(0));
        drop(j);
        let (j, r) = open(&d);
        assert_eq!((r.segments_found, r.records), (0, 0));
        assert!(!j.has_any_dirty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn append_read_overlay_and_restart() {
        let d = tmpdir("basic");
        let (j, _) = open(&d);
        let a = j.intern("dir/a");
        let b = j.intern("b");
        j.append(a, 0, b"hello world").unwrap();
        j.append(b, 4, b"xyz").unwrap();
        j.append(a, 6, b"WORLD").unwrap();
        assert_eq!(j.live_bytes(), 11 + 3);
        let got = overlay_bytes(&j, "dir/a", 11);
        assert_eq!(
            got.iter().map(|b| b.unwrap()).collect::<Vec<_>>(),
            b"hello WORLD"
        );
        assert_eq!(j.dirty_end(a), Some(11));
        assert_eq!(j.dirty_files_under("dir"), vec![a]);
        assert_eq!(j.dirty_files_under("di"), Vec::<PathId>::new());
        drop(j);

        let (j, r) = open(&d);
        assert_eq!(r.replayed_records, 3);
        assert_eq!(r.dropped_tail_bytes, 0);
        assert_eq!(j.live_bytes(), 14);
        assert_eq!(
            overlay_bytes(&j, "dir/a", 11)
                .iter()
                .map(|b| b.unwrap())
                .collect::<Vec<_>>(),
            b"hello WORLD"
        );
        // sequence numbers continue
        let a = j.file_id("dir/a").unwrap();
        assert_eq!(j.append(a, 0, b"!").unwrap(), Seq(4));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ack_trim_and_watermark_survive_restart() {
        let d = tmpdir("ack");
        let (j, _) = small(&d, 200);
        let f = j.intern("f");
        for i in 0..10u64 {
            j.append(f, i * 100, &[i as u8; 100]).unwrap();
        }
        assert!(j.segment_count() > 3);
        // acknowledge the first seven records
        let ranges = j.lock().index.dirty_ranges(f);
        for (s, len, l) in ranges.iter().take(7) {
            j.ack(
                f,
                Part {
                    offset: *s,
                    len: *len,
                    seq: l.seq,
                },
            );
        }
        assert_eq!(j.watermark(), Seq(7));
        let before = j.segment_count();
        let removed = j.trim().unwrap();
        assert!(removed > 0 && j.segment_count() == before - removed);
        drop(j);

        let (j, r) = small(&d, 200);
        assert_eq!(r.watermark, 7);
        assert_eq!(r.replayed_records, 3);
        assert_eq!(j.live_bytes(), 300);
        let f = j.file_id("f").unwrap();
        assert_eq!(j.dirty_end(f), Some(1000));
        // the replayed bytes are right
        let got = overlay_bytes(&j, "f", 1000);
        assert!(got[..700].iter().all(|b| b.is_none()));
        assert!(got[700..800].iter().all(|b| *b == Some(7)));
        assert!(got[900..].iter().all(|b| *b == Some(9)));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn idle_fully_acknowledged_journal_trims_to_nothing() {
        let d = tmpdir("idle");
        let (j, _) = open(&d);
        let f = j.intern("f");
        j.append(f, 0, &[1; 1000]).unwrap();
        let b = j.plan_batch(f, &[], 1 << 20).unwrap().unwrap();
        assert_eq!((b.offset, b.data.len(), b.path.as_str()), (0, 1000, "f"));
        for p in &b.parts {
            j.ack(f, *p);
        }
        assert_eq!(j.live_bytes(), 0);
        j.trim().unwrap();
        assert_eq!(j.segment_count(), 0);
        assert_eq!(j.disk_bytes(), 0);
        let segs = std::fs::read_dir(&d)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".wal")
            })
            .count();
        assert_eq!(segs, 0);
        // appending afterwards starts a fresh segment and keeps numbering
        assert_eq!(j.append(f, 0, b"x").unwrap(), Seq(2));
        drop(j);
        let (j, r) = open(&d);
        assert_eq!(r.watermark, 1);
        assert_eq!(j.live_bytes(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn drop_record_is_durable() {
        let d = tmpdir("drop");
        let (j, _) = open(&d);
        let f = j.intern("f");
        j.append(f, 0, &[1; 100]).unwrap();
        j.append(f, 100, &[2; 100]).unwrap();
        assert_eq!(j.drop_from(f, 100).unwrap(), 100);
        assert_eq!(j.drop_from(f, 0).unwrap(), 100);
        assert_eq!(j.drop_from(f, 0).unwrap(), 0, "nothing dirty: no record");
        assert!(!j.has_dirty(f));
        drop(j);
        let (j, _) = open(&d);
        assert_eq!(j.live_bytes(), 0, "the dropped bytes did not come back");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_deleted_file_is_not_resurrected_by_replaying_acknowledged_records() {
        let d = tmpdir("resurrect");
        let (j, _) = open(&d);
        let pinned = j.intern("pinned");
        let f = j.intern("f");
        j.append(pinned, 0, b"stuck").unwrap(); // seq 1 keeps the watermark at 0
        j.append(f, 0, &[1; 100]).unwrap();
        let b = j.plan_batch(f, &[], 1 << 20).unwrap().unwrap();
        for p in &b.parts {
            j.ack(f, *p);
        }
        assert_eq!(j.watermark(), Seq(0));
        // `f` was uploaded and then deleted on the appliance
        assert_eq!(j.drop_from(f, 0).unwrap(), 0);
        drop(j);
        let (j, _) = open(&d);
        assert_eq!(j.live_bytes(), 5, "only the pinned file is replayed");
        assert!(!j.has_dirty(j.file_id("f").unwrap()));
        // renaming a directory forgets everything below it
        let g = j.intern("dir/g");
        let h = j.intern("dirx/h");
        j.append(g, 0, b"g").unwrap();
        j.append(h, 0, b"h").unwrap();
        j.forget_under("dir").unwrap();
        assert!(!j.has_dirty(g) && j.has_dirty(h));
        drop(j);
        let (j, _) = open(&d);
        assert_eq!(j.live_bytes(), 6);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn path_table_survives_trimming_of_the_segment_that_defined_it() {
        let d = tmpdir("paths");
        let (j, _) = small(&d, 300);
        let f = j.intern("long/dir/file");
        let g = j.intern("other");
        j.append(f, 0, &[1; 200]).unwrap();
        j.append(g, 0, &[2; 200]).unwrap();
        // f's record is acknowledged, then f is written again in a later segment
        let p = j.plan_batch(f, &[], 1 << 20).unwrap().unwrap();
        for part in &p.parts {
            j.ack(f, *part);
        }
        j.append(f, 500, &[3; 200]).unwrap();
        j.trim().unwrap();
        drop(j);
        let (j, r) = small(&d, 300);
        assert!(r.corrupt_segments.is_empty());
        let got = overlay_bytes(&j, "long/dir/file", 700);
        assert!(got[500..].iter().all(|b| *b == Some(3)));
        assert!(got[..500].iter().all(|b| b.is_none()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn torn_tail_is_cut_at_every_byte_of_the_last_record() {
        let d = tmpdir("torn");
        {
            let (j, _) = open(&d);
            let f = j.intern("f");
            j.append(f, 0, &[7; 64]).unwrap();
            j.append(f, 64, &[8; 64]).unwrap();
        }
        let seg = last_segment(&d);
        let full = std::fs::read(&seg).unwrap();
        let last_record = REC_HEADER_LEN + 64;
        let keep_from = full.len() - last_record;
        for cut in keep_from..full.len() {
            std::fs::write(&seg, &full[..cut]).unwrap();
            let (j, r) = open(&d);
            assert_eq!(r.replayed_records, 1, "cut at {cut}");
            assert_eq!(
                r.dropped_tail_bytes,
                (cut - keep_from) as u64,
                "cut at {cut}"
            );
            assert!(r.corrupt_segments.is_empty());
            assert_eq!(j.live_bytes(), 64);
            // the torn bytes are gone and appending continues cleanly
            let f = j.file_id("f").unwrap();
            j.append(f, 64, &[9; 4]).unwrap();
            drop(j);
            let (j, r) = open(&d);
            assert_eq!(r.dropped_tail_bytes, 0);
            assert_eq!(j.live_bytes(), 68);
            drop(j);
            // restore for the next cut: the recovered segment was cut and a new one was added
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p != seg && p.extension().is_some_and(|e| e == "wal") {
                    std::fs::remove_file(p).unwrap();
                }
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_flipped_byte_ends_the_replay_at_that_record() {
        let d = tmpdir("flip");
        {
            let (j, _) = open(&d);
            let f = j.intern("f");
            for i in 0..3u8 {
                j.append(f, i as u64 * 10, &[i + 1; 10]).unwrap();
            }
        }
        let seg = last_segment(&d);
        let mut b = std::fs::read(&seg).unwrap();
        // the middle record's payload: after segment header, path record, one full record
        let path_rec = REC_HEADER_LEN + 1;
        let rec = REC_HEADER_LEN + 10;
        let victim = SEG_HEADER_LEN as usize + path_rec + rec + REC_HEADER_LEN + 3;
        b[victim] ^= 0x40;
        std::fs::write(&seg, &b).unwrap();
        let (j, r) = open(&d);
        // the first record is kept; the damaged one and everything after it is the torn tail
        assert_eq!(r.replayed_records, 1);
        assert_eq!(r.dropped_tail_bytes, (2 * rec) as u64);
        assert_eq!(j.live_bytes(), 10);
        // damage in the header is detected as well
        drop(j);
        let _ = std::fs::remove_dir_all(&d);
        {
            let (j, _) = open(&d);
            let f = j.intern("f");
            j.append(f, 0, &[1; 10]).unwrap();
        }
        let seg = last_segment(&d);
        let mut b = std::fs::read(&seg).unwrap();
        b[SEG_HEADER_LEN as usize + path_rec + 13] ^= 1; // inside the record header
        std::fs::write(&seg, &b).unwrap();
        let (j, r) = open(&d);
        assert_eq!(j.live_bytes(), 0);
        assert!(r.dropped_tail_bytes > 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn damage_in_an_older_segment_is_reported_not_fatal() {
        let d = tmpdir("rot");
        {
            let (j, _) = small(&d, 150);
            let f = j.intern("f");
            for i in 0..4u8 {
                j.append(f, i as u64 * 100, &[i + 1; 100]).unwrap();
            }
        }
        let mut segs: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "wal"))
            .collect();
        segs.sort();
        assert!(segs.len() >= 3);
        let mut b = std::fs::read(&segs[0]).unwrap();
        let n = b.len();
        b[n - 5] ^= 0xFF;
        std::fs::write(&segs[0], &b).unwrap();
        let (j, r) = small(&d, 150);
        assert_eq!(r.corrupt_segments.len(), 1);
        assert_eq!(j.live_bytes(), 300, "the other segments are replayed");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn garbage_files_and_bad_watermark_are_survived() {
        let d = tmpdir("garbage");
        {
            let (j, _) = open(&d);
            let f = j.intern("f");
            j.append(f, 0, b"data").unwrap();
            j.trim().unwrap();
        }
        // a segment cut right after creation (not even a header) is removed
        std::fs::write(d.join(segment_name(99)), b"JAN").unwrap();
        // a damaged watermark means "replay everything", which is safe
        std::fs::write(d.join(WATERMARK_FILE), b"nonsense").unwrap();
        // unrelated files are ignored
        std::fs::write(d.join("notes.txt"), b"x").unwrap();
        let (j, r) = open(&d);
        assert_eq!(r.watermark, 0);
        assert_eq!(j.live_bytes(), 4);
        assert!(!d.join(segment_name(99)).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_record_larger_than_the_segment_gets_its_own() {
        let d = tmpdir("big");
        let (j, _) = small(&d, 100);
        let f = j.intern("f");
        j.append(f, 0, &[5; 1000]).unwrap();
        j.append(f, 1000, &[6; 10]).unwrap();
        assert!(j.segment_count() >= 2);
        drop(j);
        let (j, _) = small(&d, 100);
        assert_eq!(j.live_bytes(), 1010);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn append_rejects_ranges_that_wrap() {
        let d = tmpdir("wrap");
        let (j, _) = open(&d);
        let f = j.intern("f");
        assert!(j.append(f, u64::MAX - 2, b"abc").is_err());
        assert!(j.append(f, u64::MAX - 3, b"abc").is_ok());
        assert_eq!(j.append(f, 0, b"").unwrap(), Seq(1));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn directory_is_0700_and_files_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("perm");
        let (j, _) = open(&d);
        let f = j.intern("f");
        j.append(f, 0, b"x").unwrap();
        j.trim().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&last_segment(&d)), 0o600);
        j.append(f, 0, b"y").unwrap();
        j.trim().unwrap();
        j.append(f, 0, b"z").unwrap();
        for e in std::fs::read_dir(&d).unwrap() {
            assert_eq!(mode(&e.unwrap().path()), 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
