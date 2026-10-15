//! WAL: the point of local durability and the read overlay (read-your-writes).
//!
//! Invariants:
//! - READ must see not-yet-uploaded writes → `read_overlay` (merging the WAL
//!   on top of data from the appliance);
//! - later-wins: overlapping writes collapse in `DirtyIndex` BEFORE upload,
//!   so reordering non-overlapping ranges on the network is safe;
//! - the segment fsync mode depends on FlushPolicy (LOCAL_JOURNAL: fsync of the WAL =
//!   the answer to F_FULLFSYNC; SYNC_THROUGH: the WAL is transit+overlay, fsync is lazy);
//! - ParkedHandleStore lives alongside: durable state survives not only a TCP
//!   drop but also a crash/restart of the daemon.

use std::collections::{BTreeMap, HashMap};

/// Monotonic WAL record number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Seq(pub u64);

/// Interned path (there are thousands of band paths, so a string in every record is wasteful).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId(pub u32);

/// Record header in a segment.
#[derive(Debug)]
pub struct RecordHeader {
    pub seq: Seq,
    pub file: PathId,
    pub offset: u64,
    pub len: u32,
    pub crc32: u32,
}

/// Where a range physically lives: a segment + the data offset within it.
#[derive(Debug, Clone, Copy)]
pub struct Loc {
    pub segment: u32,
    pub data_offset: u64,
    pub seq: Seq,
}

/// A piece of the read_overlay reply: either data from the WAL, or a hole that has to be
/// read through from the appliance.
#[derive(Debug)]
pub enum Chunk {
    Wal { offset: u64, data: Vec<u8> },
    Missing { offset: u64, len: u64 },
}

/// Per-file interval map of "dirty" ranges (later-wins).
#[derive(Debug, Default)]
pub struct DirtyIndex {
    /// file → (offset → (len, loc)); a simplified skeleton representation,
    /// the real structure is non-overlapping intervals.
    by_file: HashMap<PathId, BTreeMap<u64, (u32, Loc)>>,
}

impl DirtyIndex {
    pub fn insert(&mut self, _file: PathId, _offset: u64, _len: u32, _loc: Loc) {
        todo!("вставка с расщеплением пересечений (later-wins)")
    }

    pub fn lookup(&self, _file: PathId, _offset: u64, _len: u64) -> Vec<Chunk> {
        todo!("покрытие запроса: Wal-куски + Missing-дырки")
    }

    pub fn dirty_ranges(&self, _file: PathId) -> Vec<(u64, u32, Loc)> {
        todo!("для flush_barrier(file)")
    }
}

/// Persistence of the durable state of smb-core handles (create_guid, path, lease).
#[derive(Debug, Default)]
pub struct ParkedHandleStore;

/// Journal: append-only segments (~64 MB) + an index.
#[derive(Debug, Default)]
pub struct Journal {
    index: DirtyIndex,
    // segments: the open active one + those closed before the checkpoint
}

impl Journal {
    /// Recovery at startup: scan segments from the checkpoint → DirtyIndex +
    /// ParkedHandleStore. After a crash we continue from the same place.
    pub fn recover(_wal_dir: &std::path::Path) -> std::io::Result<Journal> {
        todo!("скан сегментов, проверка crc32, сборка индекса")
    }

    pub fn append(&mut self, _file: PathId, _offset: u64, _data: &[u8]) -> Seq {
        todo!("запись в активный сегмент + DirtyIndex.insert; Busy при переполнении")
    }

    /// Read-your-writes: WAL pieces + holes to read through from the appliance.
    pub fn read_overlay(&self, file: PathId, offset: u64, len: u64) -> Vec<Chunk> {
        self.index.lookup(file, offset, len)
    }

    /// All seq ≤ watermark are acknowledged by the appliance → trim segments.
    pub fn mark_uploaded(&mut self, _watermark: Seq) {
        todo!("checkpoint + удаление полностью подтверждённых сегментов")
    }
}
