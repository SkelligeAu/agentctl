# Multi-tenant deployment

How to run agentctl on a shared host such that compromise of one
tenant's supervised processes does not give access to another tenant's
state.

The model is **one Unix uid per tenant** with an independent agentctl
instance per uid. The kernel enforces isolation. agentctl provides
two gates that make this safe: ownership validation on the data root
and a `flock`-based single-daemon-per-root guarantee.

This document describes the operator-side setup. agentctl does **not**
provision uids, configure `/proc`, manage cgroup delegation, or set up
namespaces. Those are the operator's job, using standard system
tooling.

## Per-tenant uid creation

One Unix uid per tenant. Plain `useradd`:

```sh
useradd -r -M -s /usr/sbin/nologin tenant-foo
```

Tenants should not share any application group (`adm`, `wheel`,
`docker`, etc.) — those bypass per-uid filesystem perms. If you
delegate cgroup or `/proc` access to a group (see below), define a
**separate** admin group and put only the operator in it.

## Per-tenant systemd user unit

agentd is a long-lived foreground daemon. Run it as a systemd user
service so `loginctl enable-linger tenant-foo` materializes
`/run/user/<uid>` (with the right perms) at boot and keeps the daemon
running across logout.

```sh
loginctl enable-linger tenant-foo
```

`~tenant-foo/.config/systemd/user/agentd.service`:

```ini
[Unit]
Description=agentctl supervisor

[Service]
ExecStart=/usr/local/bin/agentd
Restart=on-failure
RestartSec=1s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=tmpfs
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

[Install]
WantedBy=default.target
```

Notes:

- `Restart=on-failure` is safe because agentctl uses `flock` for
  single-instance enforcement. A crashed daemon's lock releases
  immediately; the restart succeeds without a stale-PID race.
- `PrivateTmp=true` means this tenant's `/tmp` is private, so the
  fallback `/tmp/agentctl-<uid>` path (used when `$XDG_RUNTIME_DIR`
  is unset) is also tenant-private. Under linger, `$XDG_RUNTIME_DIR`
  is set, so the data root is `/run/user/<uid>/agentctl/` —
  per-uid, 0700 owned by the tenant, and wiped on session teardown.
- `ProtectSystem=strict` + `ProtectHome=tmpfs` reduce the blast radius
  of any agentctl bug.

Enable + start:

```sh
sudo -u tenant-foo XDG_RUNTIME_DIR=/run/user/$(id -u tenant-foo) \
    systemctl --user enable --now agentd.service
```

## `/proc` hardening

By default `/proc` shows every process to every user, leaking
`/proc/<pid>/cmdline`, `/proc/<pid>/environ` (often), and
`/proc/<pid>/maps` (always for same-uid). Mount with `hidepid=2`:

```
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc-readers 0 0
```

Members of `proc-readers` can see every process; everyone else sees
only their own. The operator goes in `proc-readers`; tenants do not.

After applying:

- `ps -e` as `tenant-foo` shows only `tenant-foo`'s processes.
- `cat /proc/<tenant-bar-pid>/maps` fails with `ENOENT`.
- pid-table enumeration via `/proc/*/` reveals only own pids.

This closes the cross-uid `/proc` leak channels.

## cgroup delegation

For agentctl's `cgroup=on` profiles to work without root, the operator
delegates a cgroup subtree to each tenant's user slice:

```sh
systemctl set-property user-$(id -u tenant-foo).slice \
    Delegate=memory+pids+cpu
```

Per-tenant resource cap at the slice level (kernel-enforced, even if
the tenant misconfigures their own profiles):

```sh
systemctl set-property user-$(id -u tenant-foo).slice \
    MemoryMax=4G
```

Per-agent cgroup limits from profiles compose under the slice cap.

## Network isolation hints

agentctl does not create network namespaces. Two choices for
tenant network isolation:

- **Hard isolation: per-tenant network namespace.** Run agentd inside
  the namespace:

  ```sh
  ip netns add tenant-foo
  ip netns exec tenant-foo \
      sudo -u tenant-foo systemctl --user start agentd
  ```

  Each tenant gets its own loopback. Cross-tenant traffic over
  loopback is impossible.

- **Soft isolation: seccomp-deny network syscalls in tenant agent
  profiles.** Add `socket(AF_INET, ...)` and `socket(AF_INET6, ...)`
  to the seccomp denylist for tenant profiles. Tenant agents cannot
  open inet sockets. Loopback is not blocked.

Pick based on threat: hard isolation needs `CAP_NET_ADMIN` to set up
once; soft isolation costs nothing but doesn't stop loopback.

## What this setup gives you

- **Filesystem isolation.** Each tenant's data root is 0700 owned by
  their uid. agentctl ownership-validates the root on every
  invocation and refuses to operate on a foreign-owned root.
- **Single-daemon-per-tenant.** agentd holds an exclusive `flock` on
  `<root>/agentd.lock` for its lifetime. Two daemons cannot run
  under the same root. The kernel releases the lock on any exit
  including SIGKILL.
- **Same-uid control acceptance.** agentd's control socket validates
  the peer's uid against its own via `SO_PEERCRED` at accept time.
  Cross-uid control connections are kernel-rejected.
- **No `/proc` leakage** between tenants (with `hidepid=2`).
- **Per-tenant cgroup quotas** (with cgroup delegation).
- **Per-tenant network isolation** (with netns, optional).

## What this setup does NOT give you

- **Intra-tenant adversarial isolation.** Two agents under the same
  tenant uid can `ptrace` each other, signal each other, and read
  each other's `/proc` entries. The broker is a logical gate inside
  one uid, not a kernel boundary. If you need adversarial isolation
  inside a tenant, use Firecracker, gVisor, or a real container
  runtime. This is the locked anti-goal in
  `docs/design-invariants.md`.
- **Side-channel resistance.** Cache attacks, timing, Spectre — use
  VMs.
- **Kernel-exploit resistance.** seccomp narrows but does not
  eliminate the kernel attack surface.
- **Cross-tenant audit aggregation.** Each tenant's
  `<root>/agentd.log` is per-uid. Centralize via journald or your
  log aggregator if needed.
- **Tooling for migrating an agent's data between tenants.** Out of
  scope.

## Verification checklist

After deploying, the operator should confirm each of these. They are
phrased as commands an operator can run.

1. **Foreign-root refusal:**
   ```sh
   sudo -u tenant-foo \
       env AGENTCTL_ROOT=/run/user/$(id -u tenant-bar)/agentctl \
       agentctl list
   ```
   Expect: non-zero exit and `"owned by uid"` on stderr.

2. **Single agentd per tenant:**
   ```sh
   sudo -u tenant-foo systemctl --user start agentd
   sudo -u tenant-foo agentd   # second invocation
   ```
   Expect: second invocation exits non-zero with `"another instance"`.

3. **`/proc` hiding:**
   ```sh
   sudo -u tenant-foo cat /proc/$(pidof -s systemd)/maps
   ```
   Expect: `ENOENT` under `hidepid=2`.

4. **cgroup quota:**
   ```sh
   systemd-cgls /user.slice/user-$(id -u tenant-foo).slice
   cat /sys/fs/cgroup/user.slice/user-$(id -u tenant-foo).slice/memory.max
   ```
   Expect: `MemoryMax` value visible and enforced.

5. **agentctl tests under this layout:**
   ```sh
   sudo -u tenant-foo XDG_RUNTIME_DIR=/run/user/$(id -u tenant-foo) \
       sh /path/to/agentctl/tests/run-all.sh
   ```
   Expect: `pass=12 fail=0`.

## Operational notes

- **Profiles dir.** `AGENT_PROFILES_DIR` should point at a
  read-only-to-the-tenant location (e.g., `/etc/agentctl/profiles/`,
  owned by the operator, mode `0755`). Tenants cannot edit profiles
  to widen their own enforcement.
- **Lockfile location.** Always at `<root>/agentd.lock`. `lsof
  <root>/agentd.lock` answers "which process holds this?" The
  lockfile is automatically removed when the data root is wiped
  (`/run/user/<uid>` on session teardown).
- **Stale state on host crash.** The data root persists across crashes
  only if the operator uses `/tmp/agentctl-<uid>` (not wiped) or a
  similar persistent path. `/run/user/<uid>` is `tmpfs` and is wiped
  on boot, which is usually what you want — every tenant starts
  clean.
- **Migrating a tenant.** Stop the daemon, `chown -R newuid:newuid
  <root>`, restart as the new uid. agentctl's ownership check will
  validate the result on first invocation under the new uid.
