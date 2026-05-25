#ifndef AGENTCTL_IPC_H
#define AGENTCTL_IPC_H

/*
 * Canonical IPC transport for agentctl. AF_UNIX, message-oriented.
 *
 * Linux:  SOCK_SEQPACKET. One sendmsg() = one logical message, one
 *         recvmsg() = one logical message. No application framing.
 * macOS:  SOCK_STREAM + LEN framing fallback (Darwin AF_UNIX does not
 *         support SOCK_SEQPACKET). macOS is dev-loop only; production
 *         target is Linux.
 *
 * Invariants (see project_agentctl_invariants):
 *   - No transport-layer userspace buffering. Kernel socket queues are
 *     the only transport queues. No application ring buffers, no batching.
 *   - Default recv cap 64 KiB; hard architectural cap 1 MiB. Senders
 *     reject above the hard cap; receivers treat MSG_TRUNC as a protocol
 *     violation.
 *   - Header is ASCII (VERB / REPLY-TO / TASK-ID, blank line, payload).
 *     On SEQPACKET there is no LEN; on STREAM fallback there is.
 *   - SCM_RIGHTS fd-passing is wired into recv from day one. n_fds=0 in
 *     ipc_msg_t when no fds were delivered. Capability broker layers on
 *     top without transport changes.
 *   - SO_PEERCRED is captured at accept() and stable for the lifetime of
 *     the connection. It identifies the *connecting* process, which may
 *     differ from the current sender if the connector fork-exec'd.
 */

#include "common.h"   /* peer_id_t, MAX_NAME, MAX_VERB, MAX_TASK_ID_INLINE */

#include <stddef.h>
#include <sys/types.h>

/* Architectural caps. */
#define IPC_MSG_DEFAULT_CAP (64u << 10)   /* 64 KiB default recv buffer */
#define IPC_MSG_HARD_CAP    (1u <<  20)   /*  1 MiB absolute architectural cap */
#define IPC_HEADER_HEADROOM 4096          /* ASCII header bytes reserved per message */
#define IPC_BUF_CAP         (IPC_MSG_HARD_CAP + IPC_HEADER_HEADROOM)

#define IPC_MAX_FDS         8             /* SCM_RIGHTS array cap */

/* Send retry policy (bounded; on exhaustion, surface EAGAIN to caller). */
#define IPC_SEND_RETRIES    3
#define IPC_SEND_BACKOFF_US { 1000, 5000, 25000 }

/* Return codes shared by ipc_send/ipc_recv/ipc_connect.
 *  0  success
 * -1  errno set; transport error
 * -2  peer is gone (EPIPE on send, EOF on recv, ECONNREFUSED on connect)
 * -3  protocol violation (MSG_TRUNC / MSG_CTRUNC / malformed header).
 *     Caller MUST close the fd. */
#define IPC_OK              0
#define IPC_ERR            (-1)
#define IPC_PEER_GONE      (-2)
#define IPC_PROTO_VIOLATION (-3)

/* One framed message. On recv, string fields and `payload` point into
 * the caller-supplied buffer; lifetime is until next ipc_recv on that
 * buffer. On send, caller owns all referenced memory. */
typedef struct {
    /* Header (parsed into pointers into the caller buffer on recv). */
    const char *verb;                       /* required */
    const char *reply_to;                   /* "" if absent */
    const char *task_id;                    /* "" if absent */

    /* Opaque payload bytes. */
    const void *payload;
    size_t      payload_len;

    /* Ancillary (recv only): fds delivered via SCM_RIGHTS. n_fds=0 normally.
     * Senders zero these out — fd-passing has a dedicated future helper. */
    int         fds[IPC_MAX_FDS];
    int         n_fds;

    /* Recv only: kernel-verified credentials of the connection's opener.
     * NOTE: identifies the connector, not necessarily the current sender. */
    peer_id_t   peer;
} ipc_msg_t;

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

/* Create a listening socket bound to <root>/agents/<name>/agent.sock.
 * Sets SOCK_CLOEXEC | SOCK_NONBLOCK on the listener. Linux: SEQPACKET.
 * macOS: STREAM. Returns server fd or -1 (errno). */
int  ipc_listen(const char *agent_name);

/* Accept one client. Captures peer creds. Result fd has SOCK_CLOEXEC set.
 * Returns client fd or -1 (errno; EAGAIN/EWOULDBLOCK propagate). */
int  ipc_accept(int server_fd, peer_id_t *out_peer);

/* Connect to <root>/agents/<target>/agent.sock.
 * Returns connected fd, IPC_PEER_GONE if no listener, or -1 on other error. */
int  ipc_connect(const char *target);

/* Close the listener and unlink the socket path. */
void ipc_close_listener(int server_fd, const char *agent_name);

/* ----------------------------------------------------------------
 * Message send / recv (one syscall per logical message)
 * ---------------------------------------------------------------- */

/* Send one message atomically. Retries EAGAIN up to IPC_SEND_RETRIES with
 * exponential backoff (1 / 5 / 25 ms), then surfaces EAGAIN to caller.
 * Rejects messages above IPC_MSG_HARD_CAP locally with EMSGSIZE.
 * Returns IPC_OK, IPC_ERR, or IPC_PEER_GONE. */
int  ipc_send(int fd, const ipc_msg_t *msg);

/* Receive one message into `buf` (must be ≥ bufcap bytes; caller-owned).
 * `bufcap` should be IPC_MSG_DEFAULT_CAP (64 KiB) for typical agents or
 * IPC_BUF_CAP for agents that must handle 1 MiB messages.
 * On IPC_OK, out_msg pointers refer into buf and out_msg->peer is filled.
 * Returns IPC_OK, IPC_ERR, IPC_PEER_GONE (EOF), or IPC_PROTO_VIOLATION. */
int  ipc_recv(int fd, void *buf, size_t bufcap, ipc_msg_t *out_msg);

/* Convenience: connect + send + close. Builds the message frame from the
 * provided header fields and payload bytes; no caller-side buffer required.
 * Returns IPC_OK, IPC_ERR, or IPC_PEER_GONE (no listener). */
int  ipc_send_oneshot(const char *target,
                      const char *verb,
                      const char *reply_to,    /* NULL or "" for absent */
                      const char *task_id,     /* NULL or "" for absent */
                      const void *payload,
                      size_t      payload_len);

#endif
