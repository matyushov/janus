# Packaging janus (Linux)

The layout is **three packages**, so the roles install independently and do not conflict
when the server and the gateway end up on the same machine.

| Package | Role | Depends on |
|---|---|---|
| `janus-receiverd` | receiving server (gRPC → store) | `janus-cli` |
| `janus-smbd` | SMB gateway (loopback SMB → backend) | `janus-cli` |
| `janus-cli` | management of both daemons | — |

## Package contents

### `janus-cli`
```
/usr/bin/janus-cli
/usr/share/doc/janus-cli/{README.md,LICENSE}
```

### `janus-receiverd`
```
/usr/bin/janus-receiverd
/lib/systemd/system/janus-receiverd.service
/usr/lib/sysusers.d/janus.conf          (the janus user)
/usr/lib/tmpfiles.d/janus.conf          (directories and permissions)
/etc/janus/receiverd.env                ← conffile (edits survive an upgrade)
/usr/share/doc/janus-receiverd/{README.md,LICENSE}
```

### `janus-smbd`
```
/usr/bin/janus-smbd
/lib/systemd/system/janus-smbd.service
/usr/lib/sysusers.d/janus.conf
/usr/lib/tmpfiles.d/janus.conf
/etc/janus/smbd.env                     ← conffile
/usr/share/doc/janus-smbd/{README.md,LICENSE}
```

## What the packages deliberately do NOT contain

- **Certificates and keys.** The mTLS identity is issued when a machine is registered
  and is not packaged. The files go into `/etc/janus/` (0750 root:janus) by hand
  or through orchestration tooling. `janus-receiverd` needs `JANUS_TLS_CERT`, `JANUS_TLS_KEY`,
  `JANUS_TLS_CA` and the machines file `JANUS_MACHINES` (see `receiverd.env`; the defaults point
  to `/etc/janus/tls/{server.pem,server.key,ca.pem}` and `/etc/janus/machines.json`) and
  refuses to start without them. Registering a machine = adding its client certificate's
  SHA-256 fingerprint to the machines file (`janus-cli server enroll` does not exist yet).
  `tools/dev-pki.sh` writes a throw-away PKI plus machines file for local trials.
- **Store data.** `/var/lib/janus/store` is created empty. It is **not erased** when the
  package is removed: it holds backups, and cleaning happens only on an explicit `purge`.
- **Autostart.** The package does not run `systemctl enable --now`: without a configuration
  and certificates the service is useless. The administrator enables it.

## Directories and permissions

| Path | Mode | Purpose |
|---|---|---|
| `/etc/janus` | `0750 root:janus` | config + certificates (read by the daemon, edited by root) |
| `/var/lib/janus/store` | `0700 janus:janus` | the receiver's store (band files) |
| `/var/lib/janus/smbd` | `0700 janus:janus` | the gateway's local journal (WAL) |
| `/run/janus` | `0750 janus:janus` | the daemons' control sockets |

The daemons run as the unprivileged `janus` user; the units are hardened
(`ProtectSystem=strict`, `ReadWritePaths` only for their own state, an empty
`CapabilityBoundingSet`, `MemoryDenyWriteExecute`, and so on).

**About port 445:** by default `janus-smbd` listens on a high port, so no privileges are
needed. For 445, uncomment `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit
(and the matching `CapabilityBoundingSet`).

## Manual installation (without a package)

```bash
install -m755 target/release/janus-receiverd /usr/bin/
install -m644 packaging/systemd/janus-receiverd.service /lib/systemd/system/
install -m644 packaging/systemd/janus-sysusers.conf     /usr/lib/sysusers.d/janus.conf
install -m644 packaging/systemd/janus-tmpfiles.conf     /usr/lib/tmpfiles.d/janus.conf
install -D -m640 packaging/systemd/janus-receiverd.env  /etc/janus/receiverd.env

systemd-sysusers && systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now janus-receiverd
```

## Building the `.deb`

The metadata is in `crates/janus-receiverd/Cargo.toml` (the
`[package.metadata.deb]` section), the maintainer scripts are in `packaging/deb/`.
Native `debian/rules` are not needed.

**Requirements:** a Linux host (the package contains an ELF binary), a Rust toolchain,
`build-essential` (the linker) and `cargo-deb`.

```bash
# once
sudo apt-get install -y build-essential
cargo install cargo-deb

# build
cargo build --release -p janus-receiverd
cargo deb -p janus-receiverd --no-build      # the .deb lands in target/debian/
```

You cannot build directly on Windows; use WSL, a container or the `ubuntu-latest` CI runner.

**Checking the contents:**
```bash
dpkg -c target/debian/janus-receiverd_*.deb    # list of files
dpkg -I target/debian/janus-receiverd_*.deb    # metadata and scripts
```

### `.rpm` (TODO)
Through [`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm), with the
same asset layout. A FreeBSD port and a Dockerfile, as needed.

### What appears after mTLS
Certificate paths in `/etc/janus/` and the corresponding parameters in
`receiverd.env`. The directory layout and the unit do not change.
