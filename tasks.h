#ifndef AGENTCTL_TASKS_H
#define AGENTCTL_TASKS_H

#include "common.h"
#include <stdarg.h>

/* "YYYYMMDDTHHMMSSZ-NNNN" = 21 chars. Round up. */
#define MAX_TASK_ID 32

/* Task ids and artifact names are path components. Keep validation in the
 * task layer so every caller receives the same traversal protection. */
int task_validate_id(const char *task_id);
int task_validate_artifact_name(const char *filename);

typedef enum {
    TASK_QUEUED = 0,
    TASK_RUNNING,
    TASK_DELEGATED,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_CANCELLED
} task_state_t;

const char *task_state_name(task_state_t s);

/* Allocate a new task id (timestamp + monotonic counter for the agent).
 * On first use per process the counter is recovered from existing task dirs. */
int task_alloc_id(const char *agent, char *out, size_t n);

/* Create the task dir and metadata files. */
int task_create(const char *agent, const char *task_id,
                const char *verb, const char *sender,
                pid_t sender_pid, uid_t sender_uid,
                const char *reply_to, const char *incoming_task_id,
                const void *payload, size_t payload_len);

/* Transitions. All atomic. */
int task_set_state (const char *agent, const char *task_id, task_state_t s);
int task_set_status(const char *agent, const char *task_id, const char *status);
int task_append_event(const char *agent, const char *task_id,
                      const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Read helpers. */
int task_read_state(const char *agent, const char *task_id, task_state_t *out);
int task_read_string(const char *agent, const char *task_id,
                     const char *leaf, char *out, size_t n);

/* Sorted iteration of task ids under <root>/agents/<agent>/tasks/. */
typedef void (*task_iter_cb)(const char *task_id, void *ud);
void task_iterate(const char *agent, task_iter_cb cb, void *ud);

/* Counts. ACTIVE = queued + running + delegated. */
int task_count_total (const char *agent);
int task_count_active(const char *agent);

/* On startup: mark queued/running/delegated tasks as failed(interrupted). */
int task_recover_interrupted(const char *agent);

/* Per-task artifact write, respecting policy (artifact_policy_t value). */
int task_write_artifact(const char *agent, const char *task_id,
                        const char *base_filename,
                        const void *buf, size_t n, int policy);

/* Pending table: <root>/agents/<agent>/pending/<task-id>.<downstream> */
int pending_add(const char *agent, const char *task_id, const char *downstream);
int pending_remove(const char *agent, const char *task_id, const char *downstream);
int pending_count_for_task(const char *agent, const char *task_id);

/* Numbered checkpoint write. Content is opaque text. */
int task_write_checkpoint(const char *agent, const char *task_id,
                          const char *content, size_t n);

#endif
