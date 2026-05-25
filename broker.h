#ifndef AGENTCTL_BROKER_H
#define AGENTCTL_BROKER_H

/*
 * broker.h — capability broker (v1, Linux-only).
 *
 * Per-agent SOCK_SEQPACKET broker channel; agentd's end held in
 * `struct managed::broker_fd`, agent's end is fd 3 in the spawned
 * runtime.
 *
 * v1 scope (locked):
 *   - fd 3 broker channel
 *   - mailbox.send:<agent> capability only
 *   - audit trail with 8-hex correlation token
 *   - broker never buffers, stores, retries, or replays application
 *     messages — it only transfers authority
 *   - mailbox.send:<agent> is short-lived: request, receive fd, send,
 *     close. Persistent peer sockets require later justification.
 *
 * NOT in v1: delegation, leases, cap discovery, filesystem caps,
 * persistent peer sockets, broker proxying, cap DB, profile hot reload.
 */

#include "common.h"

#include <stddef.h>

#define BROKER_MSG_MAX     512    /* whole header in one packet */
#define BROKER_CAP_MAX     128    /* maximum cap name length */
#define BROKER_TOKEN_LEN   8      /* 8 hex chars = 32 bits */
#define BROKER_REASON_MAX  128

/* The fd slot the agent inherits the broker channel on. */
#define BROKER_FD_SLOT     3

/* Verbs on the broker channel. */
typedef enum {
    BROKER_VERB_UNKNOWN = 0,
    BROKER_VERB_REQUEST,
    BROKER_VERB_ISSUED,
    BROKER_VERB_DENIED,
} broker_verb_t;

typedef struct {
    broker_verb_t verb;
    char          cap[BROKER_CAP_MAX];      /* cap name, e.g. mailbox.send:rb */
    char          task_id[MAX_TASK_ID_INLINE];
    char          reason[BROKER_REASON_MAX];
    char          token[BROKER_TOKEN_LEN + 1];
} broker_msg_t;

/* Parse one broker message from `buf` of length `len`. ASCII header lines
 * terminated by blank line. Returns 0 on success, -1 on malformed. */
int broker_parse(const char *buf, size_t len, broker_msg_t *out);

/* Format an "issued" response into `buf` (cap of `cap_sz`); writes the
 * actual bytes to send. Caller attaches the fd via SCM_RIGHTS separately. */
int broker_format_issued(char *buf, size_t cap_sz,
                         const char *cap, const char *token);

/* Format a "denied" response. */
int broker_format_denied(char *buf, size_t cap_sz,
                         const char *cap, const char *reason);

/* Generate an 8-char hex token (32 bits from /dev/urandom). */
void broker_make_token(char out[BROKER_TOKEN_LEN + 1]);

/* Test whether `cap_name` is permitted by `allow_patterns[]`. Each pattern
 * is exact or wildcard-suffix (e.g. "mailbox.send:*"). Returns 1 if allowed. */
int broker_policy_check(const char *cap_name,
                        const char *const *allow_patterns,
                        int n_patterns);

/* Issue mailbox.send:<target>: open a SOCK_SEQPACKET, connect to target's
 * <root>/agents/<target>/agent.sock, return the connected fd ready for SCM_RIGHTS.
 * Returns fd >= 0, -1 on local error, -2 if target has no listener. */
int broker_open_mailbox_send(const char *target);

#endif
