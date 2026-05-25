#ifndef AGENTCTL_PROFILES_H
#define AGENTCTL_PROFILES_H

#include "common.h"
#include <stdio.h>

#define MAX_PROFILE_RAW   1024
#define MAX_PROFILE_NAME  MAX_NAME

/* Enumerated policy values. Unknown strings parse to the default for the
 * category (no error — profiles are forward-compatible). */
typedef enum {
    DISPATCH_SINGLE_SHOT = 0,
    DISPATCH_PERSISTENT,
    DISPATCH_DELEGATING
} dispatch_mode_t;

typedef enum {
    ARTIFACT_OVERWRITE = 0,
    ARTIFACT_VERSIONED,
    ARTIFACT_APPEND_ONLY
} artifact_policy_t;

typedef struct {
    char              profile_name[MAX_PROFILE_NAME];
    dispatch_mode_t   dispatch;
    artifact_policy_t artifact_policy;
    int               idle_timeout_sec;       /* 0 = no timeout */

    /* Enforcement policy. Resolved into enforcement_spec_t by the supervisor
     * at start time (with CLI flags as overrides). 0 = off / unset. */
    int               enforce_fs;             /* 0=off, 1=landlock */
    int               seccomp;                /* 0=off, 1=minimal */
    int               cgroup;                 /* 0=off, 1=on */
    long              cgroup_memory_max;      /* bytes, 0 = unset */
    long              cgroup_pids_max;        /* 0 = unset */
    char              cgroup_cpu_max[32];     /* "<quota>/<period>" */

    char              raw[MAX_PROFILE_RAW];   /* on-disk profile contents */
} profile_cfg_t;

/* Symbolic name conversions. */
const char *dispatch_name(dispatch_mode_t m);
const char *artifact_policy_name(artifact_policy_t p);

/* Search PATHS for <profile_name>.profile; returns 0 + fills path_buf if found. */
int  profile_locate(const char *profile_name, char *path_buf, size_t n);

/* Read the on-disk profile file contents (NUL-terminated). 0 on success. */
int  profile_read_raw(const char *profile_name, char *out, size_t n);

/* Build defaults for `profile_name`, populating `out`. Returns 0 on success.
 * If no on-disk file exists and name is "worker", builtin defaults are used.
 * Otherwise returns -1. */
int  profile_load_by_name(const char *profile_name, profile_cfg_t *out);

/* Resolve the effective config for an agent:
 *   read <root>/agents/<name>/profile  (default "worker"),
 *   load that profile,
 *   overlay <root>/agents/<name>/config. */
int  profile_load_for_agent(const char *agent_name, profile_cfg_t *out);

/* Enumerate profile names found in search paths (dedup'd). */
typedef void (*profile_list_cb)(const char *profile_name, void *ud);
void profile_list(profile_list_cb cb, void *ud);

/* Write an artifact respecting `policy`:
 *   OVERWRITE   → atomic write to artifacts/<base>
 *   VERSIONED   → atomic write to artifacts/<stem>-<UTC-ts>.<ext>
 *   APPEND_ONLY → append `<banner><buf>` to artifacts/<base>
 * Returns 0 on success, -1 on error (errno set). */
int  write_artifact(const char *agent_name, const char *base_filename,
                    const void *buf, size_t n, artifact_policy_t policy);

/* KEY=VALUE upsert into a file. Replaces an existing line whose key matches
 * the part before '=' in `kv`, or appends if not present. Atomic write. */
int  kv_file_set(const char *path, const char *kv);

#endif
