# General-purpose long-lived process. The default profile.
# Persistent dispatch loop; snapshot on signal.
dispatch=persistent
artifact_policy=overwrite
message_policy=seqpacket
snapshot_policy=signal
idle_timeout=0
# Enforcement.
enforce_fs=landlock
seccomp=off
cgroup=on
