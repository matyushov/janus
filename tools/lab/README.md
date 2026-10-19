# janus lab scripts

Scripts for a **lab**: a macOS guest (a VM, for example UTM) that is backed up with Time Machine
through `janus-smbd` to a janus receiver (`janus-receiverd`) on another machine, and later restored
from macOS Recovery. They are what was used to bring up J4 (Time Machine compatibility) and to
check it end to end.

> **Lab use only.** The scripts change Time Machine settings and the System keychain of the machine
> they run on, take passwords from environment variables and, for Recovery, move a client private
> key by hand. Do not run them on a machine whose backups you care about, and never put real
> credentials into them.

## Topology

```
   guest (macOS VM)                                            receiver (Linux)
 +---------------------+   gRPC + mTLS (TLS 1.3)        +---------------------+
 | backupd -> SMB      |  ---------------------------->  | janus-receiverd     |
 |   127.0.0.1:4455    |   directly, or through the     | store/<machine>/... |
 | janus-smbd + journal|   reverse tunnel (tunnel.sh)   +---------------------+
 +---------------------+
        ^
        | ssh/scp from the host: push-to-guest.sh, tunnel.sh
   host (your Mac)  - holds the CA key (issue-client-cert.sh)
```

SMB never leaves the guest: it is served on loopback (`127.0.0.1:4455` in the normal system). Only the mTLS link
to the receiver crosses the network.

**In Recovery the address is different.** The restore wizard refuses `127.0.0.1`, so there the daemon listens on
`10.99.99.1:445`, an alias of `lo0` that `recovery/restore.sh` creates (nothing leaves the machine, it is still
local). In the wizard you enter `smb://<user>:<password>@10.99.99.1/<share>` with no port.

## Files

| Script | Runs on | What it does |
|---|---|---|
| `../dev-pki.sh` | host | Throw-away CA, server and client certificates and a `machines.json` (set `JANUS_DEV_SAN_EXTRA="IP:<addr>"` when the receiver is reached over the network). |
| `issue-client-cert.sh` | host (has the CA key) | Issues a client certificate for one more machine from an existing CA and writes `machines.new.json` (the old list plus the new machine). |
| `push-to-guest.sh` | host | Copies `janus-smbd`, `janus-cli`, the guest scripts and one machine's certificate to the guest. |
| `tunnel.sh` | host | Reverse SSH tunnel so that the guest reaches the receiver on its own loopback (see Gotchas). |
| `guest-daemon.sh` | guest | Starts, stops and checks `janus-smbd` (configures it for the receiver). |
| `guest-timemachine.sh` | guest | Adds the Time Machine destination, repairs the keychain entries, excludes paths, starts and waits for a backup, undoes everything. |
| `guest-dataset.sh` | guest | Generates a data set of unique random files and verifies it by SHA-256. |
| `guest-verify-restore.sh` | guest | Attaches the backup image read-only, compares a data set with the newest backup, restores one file with `tmutil restore`. |
| `bonjour-check.sh` | guest | Shows what is advertised through Bonjour. |
| `recovery/restore.sh` | Recovery | Starts the daemon in macOS Recovery so that the restore wizard can see the share. |
| `lib.sh` | - | Helpers shared by the scripts above (sourced). |

All settings are environment variables; each script lists its own in the header comment. The common ones:

| Variable | Meaning | Default |
|---|---|---|
| `JANUS_LAB_GUEST` | `user@host` of the guest (host scripts) | - |
| `JANUS_LAB_RECEIVER` | receiver `host:port` as the daemon should use it | - |
| `JANUS_LAB_PKI` | directory with `ca.pem`, `<machine>.pem`, `<machine>.key` | - |
| `JANUS_LAB_MACHINE` | machine id of that certificate | `vm-mac` |
| `JANUS_LAB_SMB_USER` / `JANUS_LAB_SMB_PASSWORD` | the single SMB account of the share | `janus` / required |
| `JANUS_LAB_SMB_ADDR` | where the daemon serves SMB | `127.0.0.1:4455` |
| `JANUS_LAB_SHARE` | share name | `backup` |
| `JANUS_LAB_DIR` | working directory on the guest | `~/j4` |
| `JANUS_LAB_SUDO_PASSWORD` | sudo password (otherwise sudo prompts) | - |

## Walk through

Build once on the host: `cargo build -p janus-smbd -p janus-cli -p janus-receiverd`.

### 1. A certificate and a place on the receiver
```
tools/lab/issue-client-cert.sh --ca-dir ~/janus-pki --out ./vm-mac-pki --machine vm-mac \
    --machines-file ~/janus-pki/machines.json
```
Put `./vm-mac-pki/machines.new.json` where the receiver reads `machines.json` (on a packaged
receiver `/etc/janus/machines.json`, mode 0600, owner `janus`) and restart `janus-receiverd`. The
receiver then creates `<store>/vm-mac/` for this machine. Without a CA yet, `tools/dev-pki.sh <dir> vm-mac`
makes everything, including a receiver certificate for `localhost`.

### 2. The guest
```
export JANUS_LAB_GUEST=user@192.168.10.127 JANUS_LAB_PKI=./vm-mac-pki JANUS_LAB_MACHINE=vm-mac
tools/lab/push-to-guest.sh
export JANUS_LAB_RECEIVER=192.168.10.135:7443
tools/lab/tunnel.sh start          # reverse tunnel, see Gotchas; prints the guest-side address
```
On the guest (over ssh), with the tunnel the receiver is `127.0.0.1:17443`:
```
export JANUS_LAB_SMB_PASSWORD=...  JANUS_LAB_RECEIVER=127.0.0.1:17443  JANUS_LAB_PKI=~/j4/pki
~/j4/lab/guest-daemon.sh start
```
The daemon must report `janus-smbd ready: connected to the server`.

### 3. Data, destination, backup
```
~/j4/lab/guest-dataset.sh make ~/tmdata --big 5 --big-mb 100
~/j4/lab/guest-timemachine.sh setup
~/j4/lab/guest-timemachine.sh exclude /Applications /Library ...   # optional: a smaller backup
~/j4/lab/guest-timemachine.sh backup --wait
```
A full backup of a fresh macOS guest is about 2 GB and takes ten minutes.

### 4. Check it
```
~/j4/lab/guest-verify-restore.sh --dataset-sha ~/tmdata.sha --subpath Users/user/tmdata \
    --file big/file1.bin
```
It prints `ALL n FILES IDENTICAL` and checks one file restored by `tmutil restore`. To test
the daemon's resilience, `kill -9` it during a backup and start it again with `guest-daemon.sh start`:
the backup continues (durable handles are reclaimed). Stopping the receiver for more than a few seconds still
kills the backup image (a known gap: CREATE does not wait for a down receiver).

### 5. Restore from Recovery
1. Shut the guest down, **clone it**, boot the original into Recovery (UTM: right click the VM, boot to Recovery).
   Connect the network, open Utilities > Terminal.
2. Bring the kit into `/tmp/janus` (Recovery has `scp`, `curl`, no `ssh` server, no `openssl`):
   copy `janus-smbd`, `janus-cli`, `<machine>.pem`, `<machine>.key`, `ca.pem` and `recovery/restore.sh`
   to the directory, for example with `scp -r user@host:kit/* .` from the host (Remote Login on).
   The key is a secret: delete the kit afterwards and revoke the machine on the receiver.
3. `sh restore.sh <receiver host:port>` (here the receiver is reached directly, with no tunnel; the Local
   Network restriction does not apply in Recovery). Then in the wizard choose "Other Server..." and enter
   `smb://janus:<password>@10.99.99.1/backup`: the wizard lists the backups with their dates.
4. Apple then says that data from such a backup must be transferred with Migration Assistant after a
   macOS reinstall. That last step has **not** been exercised with janus yet.

### 6. Undo
```
~/j4/lab/guest-timemachine.sh cleanup --snapshots
~/j4/lab/guest-daemon.sh stop
tools/lab/tunnel.sh stop                # on the host
```
Remove the machine from the receiver's `machines.json` and delete its store directory when the lab is over;
delete the kit and the certificate files of the machine.

## Gotchas (all hit while building this)

- **Keychain.** `tmutil setdestination` saves the password with port 0 and no access for `NetAuthSysAgent`;
  `backupd` then fails with error 80 ("NetAuth is not in the ACL"). `guest-timemachine.sh setup` recreates the
  entries. Check with `log show --predicate 'process == "NetAuthSysAgent"'`.
- **Local Network permission.** A third-party binary that is not started from a GUI session (ssh, nohup, launchd)
  loses access to LAN addresses after about a minute (`tcp connect error`), while `nc` and `ssh` keep it. Reaching a receiver
  on `127.0.0.1` is unaffected, hence `tunnel.sh`. Not solved for a LaunchAgent: plan J5.
- **Capabilities.** The NEGOTIATE reply must advertise `LEASING` for the Time Machine profile, otherwise the kernel answers
  "Operation not supported" (error 45); advertising persistent handles or directory leasing makes the client drop the
  connection. The AAPL reply needs `FULL_SYNC` in the **volume** capabilities.
- **Recovery wizard.** It rejects `127.0.0.1`; use the lo0 alias address (`recovery/restore.sh`). `pkill` does not work
  there: the script kills by pid. Do not mount the share and press Connect for the same server at the same time: the
  wizard then reports a connection problem.
- **Folder names inside the image.** After a finished backup the newest folder is `*.previous`, not `*.backup`; the
  states of both backups are APFS snapshots (`diskutil apfs listSnapshots`).
- **Guest python3.** On a guest without developer tools `python3` is a stub that opens an install dialog: the scripts use
  only the shell and system tools there.
- **Passwords.** `tmutil setdestination` takes the password on its command line (visible in `ps` for a moment).
  That is acceptable in a lab and the reason for the warning at the top.

## Symptom -> cause

| What you see | Cause |
|---|---|
| `tmutil setdestination`: error 45 "Operation not supported" | no `LEASING` in NEGOTIATE, or no `FULL_SYNC` in the AAPL reply (log: "does not support SMB FullFSync") |
| `backupd`: `BACKUP_FAILED_AUTHENTICATION_ERROR (29)`, error 80 | keychain entry missing, wrong port or no access for `NetAuthSysAgent`: `guest-timemachine.sh setup` |
| `tmutil setdestination`: error 5 (EIO) | the daemon cannot reach the receiver (`janus-cli client ready`); the first request after `configure` was also seen failing once while the link was being set up (not isolated) |
| `ready`: "tcp connect error" about a minute after the start | Local Network permission (see Gotchas): use `tunnel.sh` |
| `BACKUP_FAILED_DISCONNECTED_DISK_IMAGE (70)` | the receiver was down: CREATE fails at once, `diskimagesiod` ejects the image (known gap) |
| `BACKUP_FAILED_DISCONNECTED_NETWORK (26)` right after `kill -9` | a durable handle was lost (fixed: handles are persisted when granted); a hit if `parked-handles.json` is missing |
| `BACKUP_FAILED_NO_SUCH_DESTINATION (47)` | the destination was removed (after `cleanup`) |
| Recovery wizard: "problem connecting to the server" | wrong address (it refuses `127.0.0.1`), nothing listening on `10.99.99.1:445`, or an old daemon still holds the control port |
| receiver log: "TLS handshake eof" | harmless, an `nc -z` probe |
| many `TMStructure ... Expected ... metadata type` errors in the Time Machine log | harmless noise |

## Recovery tips

- Time Machine's progress percentage is not a size: it showed 9.5 GB planned for a backup that copied 1.7 GB.
  `tmutil addexclusion -p` applied only partly, so do not count on it for sizing. A full backup of a fresh macOS guest takes
  about ten minutes; sparsebundle bands are 256 MB each, so the store holds more than the data.
- In Recovery `hdiutil attach` of the bundle is silent and can take minutes; do not interrupt it. `pkill` does not work: kill by pid.
  `scp` needs `-o StrictHostKeyChecking=accept-new` the first time, and the Terminal history (up arrow) saves retyping.
- The VM window may swallow keys (the host takes Cmd-Tab) and the clipboard is not shared in Recovery: open a second Terminal from
  Utilities > Terminal instead of switching windows, and type short commands. If `janus-cli client ready` is fine but a mount
  times out, check that no old daemon is running (a new daemon that cannot take the control port exits, and the old one answers).
- The lab runs the daemon as `janus-smbd --dev` with the SMB account from the environment, not under launchd.

Tests of the scripts: `bash -n` on every script and local runs of `issue-client-cert.sh` and `guest-dataset.sh`.
The rest was run by hand on a macOS 26.6.2 arm64 guest and a Linux receiver while building J4, but the scripts themselves
have not been run end to end in this form.
