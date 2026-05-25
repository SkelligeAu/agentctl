# Single-shot stateless work.
# Process one message, write artifacts, exit after a short idle window.
dispatch=single-shot
artifact_policy=overwrite
message_policy=seqpacket
snapshot_policy=signal
idle_timeout=30
# Enforcement.
enforce_fs=landlock
seccomp=minimal
cgroup=off
