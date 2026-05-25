#ifndef AGENTCTL_ENFORCEMENT_H
#define AGENTCTL_ENFORCEMENT_H

#include "common.h"

/* What the supervisor was asked to apply. */
typedef enum { ENFORCE_FS_OFF = 0, ENFORCE_FS_LANDLOCK } enforce_fs_mode_t;
typedef enum { SECCOMP_OFF      = 0, SECCOMP_MINIMAL   } seccomp_mode_t;

typedef struct {
    enforce_fs_mode_t fs_mode;
    seccomp_mode_t    sc_mode;
    int               cgroup_on;        /* 0|1 */
    long              cg_memory_max;    /* bytes; 0 = unset */
    long              cg_pids_max;      /* count;  0 = unset */
    char              cg_cpu_max[32];   /* "<quota>/<period>"; "" = unset */
} enforcement_spec_t;

/* What was actually applied. Persisted to <root>/agents/<name>/enforcement.applied. */
#define ENF_STATUS_INACTIVE     0
#define ENF_STATUS_ACTIVE       1
#define ENF_STATUS_UNAVAILABLE  (-1)

typedef struct {
    int  landlock_status;
    int  landlock_rules;
    int  seccomp_status;
    int  cgroup_status;
    char cgroup_path[256];
    char reason[256];
} enforcement_state_t;

/* String forms (stable; used by audit/inspect/psa). */
const char *enforce_fs_name(enforce_fs_mode_t m);
const char *seccomp_mode_name(seccomp_mode_t m);
const char *enforce_status_word(int status);  /* "active" "inactive" "unavailable" */

/* Parent: write enforcement.req describing what is being attempted. */
int enforcement_write_req(const char *agent_name, const enforcement_spec_t *spec);

/* Parent: set up cgroup if requested. Records result into `state`. Linux-only;
 * on other platforms returns 0 with state->cgroup_status = UNAVAILABLE. */
int enforcement_parent_setup(const char *agent_name,
                              const enforcement_spec_t *spec,
                              enforcement_state_t *state);

/* Parent: after fork, push child pid into the cgroup if it was set up. */
int enforcement_parent_attach_pid(const enforcement_state_t *state, pid_t pid);

/* Child: apply landlock + seccomp, writes the full enforcement.applied file
 * (merging in cgroup state passed in `state`). cwd is the agent dir. */
int enforcement_child_apply(const char *agent_name,
                             const enforcement_spec_t *spec,
                             enforcement_state_t *state);

/* Read enforcement.applied off disk. Missing file → state all-inactive. */
int enforcement_read_state(const char *agent_name, enforcement_state_t *out);

/* Audit one line per backend describing the applied state. Called by
 * runtimes at startup so the post-exec enforcement decisions land in
 * the same audit.log as everything else. */
void enforcement_audit_status(const char *agent_name);

#endif
