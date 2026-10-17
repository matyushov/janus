#!/usr/bin/env python3
"""Summarise a janus-smbd trace taken with JANUS_SMB_TRACE=2.

    JANUS_SMB_TRACE=2 janus-smbd ... > smbd.log 2>&1
    tools/smb-trace-summary.py smbd.log [--seq]

Reads the "raw → <hex>" request dumps (compound requests are expanded) and the "←" reply
status lines, and prints counts of: commands, CREATE contexts (name, data size), CREATE
options/dispositions/access, IOCTL/FSCTL codes, QUERY_INFO/SET_INFO/QUERY_DIRECTORY classes,
FLUSH Reserved1 values, LOCK and the reply statuses per command. READ/WRITE bodies are never
printed. With --seq the per-request sequence is printed as well.
"""
import re
import struct
import sys
from collections import Counter, defaultdict

CMD = ["NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT", "TREE_DISCONNECT", "CREATE", "CLOSE",
       "FLUSH", "READ", "WRITE", "LOCK", "IOCTL", "CANCEL", "ECHO", "QUERY_DIRECTORY",
       "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"]
INFO_FILE = {1: "FileDirectoryInformation", 2: "FileFullDirectoryInformation", 3: "FileBothDirectoryInformation",
             4: "FileBasicInformation", 5: "FileStandardInformation", 6: "FileInternalInformation",
             7: "FileEaInformation", 8: "FileAccessInformation", 9: "FileNameInformation",
             10: "FileRenameInformation", 11: "FileLinkInformation", 12: "FileNamesInformation",
             13: "FileDispositionInformation", 14: "FilePositionInformation", 16: "FileModeInformation",
             17: "FileAlignmentInformation", 18: "FileAllInformation", 19: "FileAllocationInformation",
             20: "FileEndOfFileInformation", 21: "FileAlternateNameInformation", 22: "FileStreamInformation",
             23: "FilePipeInformation", 28: "FileCompressionInformation", 34: "FileNetworkOpenInformation",
             35: "FileAttributeTagInformation", 37: "FileIdBothDirectoryInformation",
             38: "FileIdFullDirectoryInformation", 43: "FileValidDataLengthInformation",
             44: "FileShortNameInformation", 59: "FileRenameInformationEx", 64: "FileDispositionInformationEx"}
INFO_FS = {1: "FileFsVolumeInformation", 3: "FileFsSizeInformation", 4: "FileFsDeviceInformation",
           5: "FileFsAttributeInformation", 6: "FileFsControlInformation", 7: "FileFsFullSizeInformation",
           8: "FileFsObjectIdInformation", 11: "FileFsSectorSizeInformation"}
FSCTL = {0x00060194: "FSCTL_DFS_GET_REFERRALS", 0x0011c017: "FSCTL_PIPE_TRANSCEIVE",
         0x00140204: "FSCTL_VALIDATE_NEGOTIATE_INFO", 0x00090000: "FSCTL_REQUEST_OPLOCK_LEVEL_1",
         0x00098208: "FSCTL_SRV_COPYCHUNK", 0x001440f2: "FSCTL_SRV_COPYCHUNK_WRITE",
         0x001401fc: "FSCTL_QUERY_NETWORK_INTERFACE_INFO", 0x00144064: "FSCTL_SRV_ENUMERATE_SNAPSHOTS",
         0x00140078: "FSCTL_SRV_REQUEST_RESUME_KEY", 0x000900a4: "FSCTL_SET_REPARSE_POINT",
         0x000900a8: "FSCTL_GET_REPARSE_POINT", 0x000980c8: "FSCTL_SET_ZERO_DATA",
         0x0009c040: "FSCTL_SET_SPARSE", 0x000940cf: "FSCTL_QUERY_ALLOCATED_RANGES",
         0x00098344: "FSCTL_DUPLICATE_EXTENTS_TO_FILE", 0x00090060: "FSCTL_SET_COMPRESSION",
         0x00090018: "FSCTL_LOCK_VOLUME", 0x0009009c: "FSCTL_GET_INTEGRITY_INFORMATION",
         0x00094264: "FSCTL_OFFLOAD_READ", 0x00098268: "FSCTL_OFFLOAD_WRITE",
         0x00110018: "FSCTL_PIPE_WAIT"}


def hex_info(table, v):
    return table.get(v, f"class {v}")


def create_contexts(msg, base):
    off, ln = struct.unpack_from("<II", msg, base + 48)
    out = []
    if not off or not ln:
        return out
    pos = off
    while True:
        nxt, noff, nlen, _, doff, dlen = struct.unpack_from("<IHHHHI", msg, pos)
        name = msg[pos + noff:pos + noff + nlen]
        label = name.decode("latin1") if name.isascii() else name.hex()
        # DH2Q/DH2C/RqLs carry their parameters in the data; keep a short digest.
        data = msg[pos + doff:pos + doff + dlen]
        out.append((label, dlen, data))
        if not nxt:
            break
        pos += nxt
    return out


def split_compound(raw):
    pos = 0
    while pos + 64 <= len(raw):
        nxt = struct.unpack_from("<I", raw, pos + 20)[0]
        end = pos + nxt if nxt else len(raw)
        yield raw[pos:end]
        if not nxt:
            break
        pos = end


def main():
    path = sys.argv[1]
    seq = "--seq" in sys.argv
    cmds, ctxs, creates, fsctls, infos, flush, statuses = (Counter() for _ in range(7))
    lock_n = Counter()
    ctx_detail = {}
    reply_status = defaultdict(Counter)
    mid_cmd = {}
    lines = open(path, errors="replace").read().splitlines()
    for ln in lines:
        m = re.search(r"raw → ([0-9a-f]+)$", ln)
        if not m:
            continue
        raw = bytes.fromhex(m.group(1))
        if raw[:4] != b"\xfeSMB":
            continue
        for msg in split_compound(raw):
            cmd = struct.unpack_from("<H", msg, 12)[0]
            mid = struct.unpack_from("<Q", msg, 24)[0]
            name = CMD[cmd] if cmd < len(CMD) else f"cmd{cmd}"
            mid_cmd[mid] = name
            cmds[name] += 1
            note = ""
            b = 64
            if name == "CREATE" and len(msg) >= b + 56:
                oplock = msg[b + 3]
                acc, attr, share, disp, opts = struct.unpack_from("<IIIII", msg, b + 24)
                creates[f"disposition={disp} options={opts:#x} share={share:#x} oplock={oplock:#x}"] += 1
                cs = create_contexts(msg, b)
                for cn, dl, data in cs:
                    ctxs[f"{cn} (data {dl} B)"] += 1
                    ctx_detail.setdefault(cn, data[:48].hex())
                noff, nlen = struct.unpack_from("<HH", msg, b + 44)
                path = msg[noff:noff + nlen].decode("utf-16le", "replace")
                note = f" {path!r}" + (" ctx=" + ",".join(c[0] for c in cs) if cs else "")
                note += f" access={acc:#x} opts={opts:#x} disp={disp}"
            elif name == "IOCTL":
                code = struct.unpack_from("<I", msg, b + 4)[0]
                label = FSCTL.get(code, f"{code:#010x}")
                fsctls[label] += 1
                note = " " + label
            elif name in ("QUERY_INFO", "SET_INFO"):
                itype, cls = msg[b + 2], msg[b + 3]
                tbl = {1: INFO_FILE, 2: INFO_FS}.get(itype, {})
                label = {1: "file", 2: "fs", 3: "security", 4: "quota"}.get(itype, "?") + ":" + hex_info(tbl, cls)
                infos[f"{name} {label}"] += 1
                note = " " + label
            elif name == "QUERY_DIRECTORY":
                infos[f"QUERY_DIRECTORY {hex_info(INFO_FILE, msg[b + 2])}"] += 1
            elif name == "FLUSH":
                r1 = struct.unpack_from("<H", msg, b + 2)[0]
                flush[f"Reserved1={r1:#06x}"] += 1
                note = f" Reserved1={r1:#06x}"
            elif name == "LOCK":
                count = struct.unpack_from("<H", msg, b + 2)[0]
                flags = struct.unpack_from("<I", msg, b + 40)[0] if len(msg) >= b + 44 else 0
                lock_n[f"count={count} flags={flags:#x}"] += 1
                note = f" flags={flags:#x}"
            if seq:
                print(f"mid={mid:<5} {name}{note}")
    for ln in lines:
        m = re.search(r"← (.*)$", ln)
        if not m:
            continue
        for part in m.group(1).split(" | "):
            mm = re.search(r"mid=(\d+).*status=(0x[0-9a-f]+)", part)
            if mm and int(mm.group(1)) in mid_cmd:
                reply_status[mid_cmd[int(mm.group(1))]][mm.group(2)] += 1

    def dump(title, counter):
        if counter:
            print(f"\n== {title}")
            for k, v in counter.most_common():
                print(f"  {v:6}  {k}")

    dump("commands", cmds)
    dump("CREATE shapes", creates)
    dump("CREATE contexts", ctxs)
    for k, v in ctx_detail.items():
        print(f"  first data of {k}: {v}")
    dump("FSCTL codes", fsctls)
    dump("info classes", infos)
    dump("FLUSH", flush)
    dump("LOCK", lock_n)
    print("\n== reply statuses")
    for c, cnt in sorted(reply_status.items()):
        print(f"  {c}: " + ", ".join(f"{s} x{n}" for s, n in cnt.most_common()))


if __name__ == "__main__":
    main()
