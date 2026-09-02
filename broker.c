/*
 * broker.c — capability broker (v1, Linux-only).
 *
 * Parser, response formatter, policy check, and mailbox.send opener.
 * The agentd-side handler that drives this lives in agentd.c.
 *
 * Anti-goals reaffirmed inline:
 *   - no buffering, no retries, no replay
 *   - no introspection ("list my caps") — agents use /proc/self/fd/
 *   - no delegation in v1
 *   - no leases in v1
 */

#include "broker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#if !defined(SOCK_CLOEXEC)
#  define SOCK_CLOEXEC 0
#endif

/* ---------- token generation ---------- */

void broker_make_token(char out[BROKER_TOKEN_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char r[4] = {0};
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, r, sizeof(r));
        (void)n;
        close(fd);
    }
    for (int i = 0; i < 4; i++) {
        out[i * 2]     = hex[(r[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[r[i] & 0xf];
    }
    out[BROKER_TOKEN_LEN] = '\0';
}

/* ---------- parser ---------- */

static void copy_field(char *dst, size_t cap, const char *src, size_t len)
{
    if (len >= cap) len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

int broker_parse(const char *buf, size_t len, broker_msg_t *out)
{
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));

    const char *p   = buf;
    const char *end = buf + len;
    int got_verb = 0;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) return -1;
        size_t llen = (size_t)(eol - p);
        if (llen == 0) { /* blank — end of header */ break; }

        if (llen >= 5 && memcmp(p, "VERB ", 5) == 0) {
            const char *v = p + 5;
            size_t vl = llen - 5;
            while (vl > 0 && *v == ' ') { v++; vl--; }
            if      (vl == 7 && memcmp(v, "request", 7) == 0) out->verb = BROKER_VERB_REQUEST;
            else if (vl == 6 && memcmp(v, "issued",  6) == 0) out->verb = BROKER_VERB_ISSUED;
            else if (vl == 6 && memcmp(v, "denied",  6) == 0) out->verb = BROKER_VERB_DENIED;
            else return -1;
            got_verb = 1;
        } else if (llen >= 4 && memcmp(p, "CAP ", 4) == 0) {
            const char *v = p + 4;
            size_t vl = llen - 4;
            while (vl > 0 && *v == ' ') { v++; vl--; }
            copy_field(out->cap, sizeof(out->cap), v, vl);
        } else if (llen >= 8 && memcmp(p, "TASK-ID ", 8) == 0) {
            const char *v = p + 8;
            size_t vl = llen - 8;
            while (vl > 0 && *v == ' ') { v++; vl--; }
            copy_field(out->task_id, sizeof(out->task_id), v, vl);
        } else if (llen >= 7 && memcmp(p, "REASON ", 7) == 0) {
            const char *v = p + 7;
            size_t vl = llen - 7;
            while (vl > 0 && *v == ' ') { v++; vl--; }
            copy_field(out->reason, sizeof(out->reason), v, vl);
        } else if (llen >= 6 && memcmp(p, "TOKEN ", 6) == 0) {
            const char *v = p + 6;
            size_t vl = llen - 6;
            while (vl > 0 && *v == ' ') { v++; vl--; }
            copy_field(out->token, sizeof(out->token), v, vl);
        }
        /* unknown headers ignored — forward-compat */
        p = eol + 1;
    }
    if (!got_verb) return -1;
    return 0;
}

/* ---------- formatters ---------- */

int broker_format_issued(char *buf, size_t cap_sz,
                         const char *cap, const char *token)
{
    if (!cap || !token) { errno = EINVAL; return -1; }
    int n = snprintf(buf, cap_sz,
                     "VERB issued\nCAP %s\nTOKEN %s\n\n", cap, token);
    if (n < 0 || (size_t)n >= cap_sz) { errno = EOVERFLOW; return -1; }
    return n;
}

int broker_format_denied(char *buf, size_t cap_sz,
                         const char *cap, const char *reason)
{
    if (!cap) { errno = EINVAL; return -1; }
    int n = snprintf(buf, cap_sz,
                     "VERB denied\nCAP %s\nREASON %s\n\n",
                     cap, reason ? reason : "not-permitted");
    if (n < 0 || (size_t)n >= cap_sz) { errno = EOVERFLOW; return -1; }
    return n;
}

/* ---------- policy check ---------- */

/* Returns 1 if `name` matches `pattern` (exact, or pattern ending in `*`
 * matching that prefix). */
static int pattern_match(const char *pattern, const char *name)
{
    if (!pattern || !name) return 0;
    size_t pl = strlen(pattern);
    if (pl == 0) return 0;
    if (pattern[pl - 1] == '*') {
        return strncmp(pattern, name, pl - 1) == 0;
    }
    return strcmp(pattern, name) == 0;
}

int broker_policy_check(const char *cap_name,
                        const char *const *allow_patterns,
                        int n_patterns)
{
    if (!cap_name || !allow_patterns) return 0;
    for (int i = 0; i < n_patterns; i++) {
        if (pattern_match(allow_patterns[i], cap_name)) return 1;
    }
    return 0;
}
