# Multiple-user deployment

A tenant is a UNIX account that runs its own agentctl instance.
Use a separate account for each user who must not access another user's state.

UNIX permissions provide the account boundary.
The agentctl root checks and daemon lock do not provide complete host isolation.
Read [SECURITY.md](../SECURITY.md) before deployment.

The host administrator must create accounts and configure process visibility, cgroups and network access.
agentctl does not perform that setup.

## Create an account

```sh
useradd -r -M -s /usr/sbin/nologin tenant-foo
```

This command creates a system account without a home directory.
Create and configure a home directory separately if you use systemd user units.

Do not grant tenant accounts access to privileged groups such as `docker`, `adm` or `wheel`.
Do not use a shared group to expose tenant state directories.
Keep any process-inspection administrator group separate from tenant accounts.

## Run the supervisor

`agentd` runs in the foreground.
A systemd user service can manage it.

Enable lingering if the user service must run without a login session:

```sh
loginctl enable-linger tenant-foo
```

Example user unit at `~tenant-foo/.config/systemd/user/agentd.service`:

```ini
[Unit]
Description=agentctl supervisor

[Service]
ExecStart=/usr/local/bin/agentd
Environment=AGENT_PROFILES_DIR=/etc/agentctl/profiles
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

This is a service example, not a complete isolation configuration.
Check the settings supported by the host's systemd installation.

`ProtectControlGroups=true` prevents cgroup writes.
Do not use this setting when the service must configure resource limits.
Removing it alone does not establish safe cgroup delegation.

Start the service after installing the unit:

```sh
sudo -u tenant-foo XDG_RUNTIME_DIR=/run/user/$(id -u tenant-foo) \
    systemctl --user enable --now agentd.service
```

The daemon lock prevents a second instance under the same state root.
The kernel releases the lock after daemon exit.
Recovery of already running agents has separate identity limits.
See [process control limits](../SECURITY.md#process-control-limits).

With `XDG_RUNTIME_DIR` set, the root is normally `/run/user/<uid>/agentctl`.
Without it, the fallback is `/tmp/agentctl-<uid>`.
`PrivateTmp=true` gives the service a private temporary directory.
Operator tools must use the same visible state root as the daemon.

## Restrict process visibility

The host's `/proc` mount controls process visibility.
A `hidepid=2` mount can hide other users' process directories.

Example fstab entry:

```text
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc-readers 0 0
```

Configure the `proc-readers` group for the host before using this entry.
Do not add tenant accounts to a group that bypasses the visibility restriction.

Verify the mount and test access from each account.
Use a known process owned by another account.
Access should fail under the intended configuration.
The error text depends on the host and mount settings.

This does not isolate agents that share one user ID.

## Configure cgroup limits

The current supervisor uses `/sys/fs/cgroup/agents/<name>`.
It does not automatically select a systemd user-slice subtree.

Delegating a user slice alone does not make that path usable.
Do not grant several untrusted accounts write access to the same cgroup parent.
Provide a compatible private hierarchy before relying on per-agent limits.

The delegated hierarchy needs the memory, PID and CPU controllers.
The supervisor must have permission to create its agent cgroups and move its children into them.
Controller delegation also requires the correct permissions on the common ancestor.

A host-level slice limit can bound processes that remain in that slice.
For example:

```sh
systemctl set-property user-$(id -u tenant-foo).slice MemoryMax=4G
```

Verify process membership.
Do not assume the supervisor's hardcoded agent path composes with this slice limit.

With cgroup enforcement enabled, configured limits must be written successfully before startup.
Invalid CPU quotas and failed controller writes return an error.
Without configured limits, unavailable cgroups retain the process-group fallback.

Cgroup attachment occurs after `fork`. A startup gate keeps the child from
executing its runtime until attachment succeeds. Failed attachment refuses
startup. Parent-death fault injection at this gate remains unverified; retain
an outer host boundary and independent cleanup watchdog.

## Configure network access

agentctl does not create network namespaces.
The minimal seccomp filter permits socket calls.
There is no configurable network-syscall denylist in that filter.

A host administrator can place the daemon in a network namespace.
The namespace also needs its own routing, interface and firewall setup.

Starting `systemctl` inside a namespace does not place a service there.
The service manager controls where the service runs.
Configure the service or start the daemon directly in the intended namespace.

Verify the daemon's network namespace and test permitted and denied connections.
Do not infer network isolation from separate UNIX user IDs.

## Verify the deployment

### State root

Test access to another user's root:

```sh
sudo -u tenant-foo \
    env AGENTCTL_ROOT=/run/user/$(id -u tenant-bar)/agentctl \
    agentctl list
```

Expect a nonzero exit.
The error should indicate failed access, ownership or permission checks.

### Daemon lock

With the service already running, start another daemon under the same root:

```sh
sudo -u tenant-foo XDG_RUNTIME_DIR=/run/user/$(id -u tenant-foo) agentd
```

Expect a nonzero exit and an `another instance` message.
Confirm that both commands resolve to the same state root.

### Process visibility and limits

Test another user's known PID through `/proc`.
Check that access fails as required.

Inspect cgroup membership and the actual limit files:

```sh
systemd-cgls /user.slice/user-$(id -u tenant-foo).slice
cat /sys/fs/cgroup/user.slice/user-$(id -u tenant-foo).slice/memory.max
```

A configured value alone does not prove enforcement.
Run bounded workloads and check kernel counters.
Use a disposable VM for resource exhaustion and subtree termination tests.

### Test suite

Build the programs and start the test daemon first.
Use the tenant's runtime directory:

```sh
sudo -u tenant-foo XDG_RUNTIME_DIR=/run/user/$(id -u tenant-foo) \
    sh /path/to/agentctl/tests/run-all.sh
```

Inspect failures and skipped checks.
Some checks need privileges unavailable to a tenant account.
See [test instructions](../tests/README.md).

## Operation

Keep shared profiles in an operator-owned directory, such as `/etc/agentctl/profiles`.
Set `AGENT_PROFILES_DIR` explicitly.
Do not let tenants change profiles if the host depends on those restrictions.

The daemon lock is `<root>/agentd.lock`.
Use `lsof <root>/agentd.lock` to inspect its holder.

`/run/user/<uid>` is temporary state.
Do not rely on it surviving a reboot.
The retention policy for `/tmp` depends on the host.
Use an explicit persistent `AGENTCTL_ROOT` if persistence is required.

Collect logs separately if records must cover several accounts.
agentctl does not provide cross-user log collection or data migration tools.

Before moving state to another account, stop the daemon and all related processes.
Review directory ownership, file permissions, profiles, cgroup placement and retained descriptors before restarting.

Separate accounts do not prevent kernel exploits or side channels.
They also do not isolate hostile agents within one account.
