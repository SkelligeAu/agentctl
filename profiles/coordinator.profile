# Coordination and fanout. (File renamed to coordinator.profile.)
dispatch=delegating
artifact_policy=overwrite
message_policy=seqpacket
snapshot_policy=signal
idle_timeout=0
# Enforcement.
enforce_fs=landlock
seccomp=off
cgroup=on
