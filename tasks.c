#include "tasks.h"
#include "profiles.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---------- state name table ---------- */

const char *task_state_name(task_state_t s)
{
    switch (s) {
        case TASK_QUEUED:    return "queued";
        case TASK_RUNNING:   return "running";
        case TASK_DELEGATED: return "delegated";
        case TASK_COMPLETED: return "completed";
        case TASK_FAILED:    return "failed";
        case TASK_CANCELLED: return "cancelled";
    }
    return "?";
}

static int parse_state(const char *s, task_state_t *out)
{
    if      (strcmp(s, "queued")    == 0) *out = TASK_QUEUED;
    else if (strcmp(s, "running")   == 0) *out = TASK_RUNNING;
    else if (strcmp(s, "delegated") == 0) *out = TASK_DELEGATED;
    else if (strcmp(s, "completed") == 0) *out = TASK_COMPLETED;
    else if (strcmp(s, "failed")    == 0) *out = TASK_FAILED;
    else if (strcmp(s, "cancelled") == 0) *out = TASK_CANCELLED;
    else return -1;
    return 0;
}

/* ---------- path helpers ---------- */

static int validate_path_component(const char *value, size_t max_len)
{
    if (!value) return -1;
    size_t len = strlen(value);
    if (len == 0 || len > max_len || value[0] == '.') return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) return -1;
    }
    return 0;
}

int task_validate_id(const char *task_id)
{
    return validate_path_component(task_id, MAX_TASK_ID - 1);
}

int task_validate_artifact_name(const char *filename)
{
    return validate_path_component(filename, 127);
}

static int task_leaf_path(const char *agent, const char *task_id,
                          const char *leaf, char *out, size_t n)
{
    if (task_validate_id(task_id) != 0) { errno = EINVAL; return -1; }
    char rel[256];
    int r = snprintf(rel, sizeof(rel), "tasks/%s%s%s",
                     task_id, leaf[0] ? "/" : "", leaf);
    if (r < 0 || (size_t)r >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
    return agent_path(out, n, agent, rel);
}

static int tasks_root(const char *agent, char *out, size_t n)
{
    return agent_path(out, n, agent, "tasks");
}

/* ---------- ID allocation ---------- */

/* Per-process counter, recovered on first use. Indexed by agent name —
 * with a tiny lookup table since a process is one runtime + maybe a few
 * agentctl invocations. */

struct seq_entry { char agent[MAX_NAME]; long next; };
#define MAX_SEQ_AGENTS 4
static struct seq_entry g_seq[MAX_SEQ_AGENTS];
static int g_seq_n = 0;

static long load_max_seq(const char *agent)
{
    char root[MAX_PATHBUF];
    if (tasks_root(agent, root, sizeof(root)) != 0) return 0;
    DIR *d = opendir(root);
    if (!d) return 0;
    long max_n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        const char *dash = strrchr(e->d_name, '-');
        if (!dash) continue;
        char *end;
        long v = strtol(dash + 1, &end, 10);
        if (v > max_n) max_n = v;
    }
    closedir(d);
    return max_n;
}

static long get_next_seq(const char *agent)
{
    for (int i = 0; i < g_seq_n; i++) {
        if (strcmp(g_seq[i].agent, agent) == 0) {
            return ++g_seq[i].next;
        }
    }
    if (g_seq_n < MAX_SEQ_AGENTS) {
        snprintf(g_seq[g_seq_n].agent, sizeof(g_seq[g_seq_n].agent), "%s", agent);
        g_seq[g_seq_n].next = load_max_seq(agent) + 1;
        return g_seq[g_seq_n++].next;
    }
    /* Fallback: rescan every time. */
    return load_max_seq(agent) + 1;
}

int task_alloc_id(const char *agent, char *out, size_t n)
{
    if (validate_name(agent) != 0) { errno = EINVAL; return -1; }
    long seq = get_next_seq(agent);
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    int r = snprintf(out, n, "%04d%02d%02dT%02d%02d%02dZ-%04ld",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec, seq);
    if (r < 0 || (size_t)r >= n) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

/* ---------- create + state + events ---------- */

static int task_dir(const char *agent, const char *task_id,
                    char *out, size_t n)
{
    return task_leaf_path(agent, task_id, "", out, n);
}

static int write_iso_now(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    return snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02dZ\n",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int write_text_line(const char *agent, const char *task_id,
                           const char *leaf, const char *value)
{
    char p[MAX_PATHBUF];
    if (task_leaf_path(agent, task_id, leaf, p, sizeof(p)) != 0) return -1;
    size_t l = strlen(value);
    char buf[1024];
    if (l + 2 > sizeof(buf)) { errno = E2BIG; return -1; }
    memcpy(buf, value, l);
    buf[l] = '\n';
    return atomic_write_file(p, buf, l + 1, 0600);
}

int task_create(const char *agent, const char *task_id,
                const char *verb, const char *sender,
                pid_t sender_pid, uid_t sender_uid,
                const char *reply_to, const char *incoming_task_id,
                const void *payload, size_t payload_len)
{
    if (task_validate_id(task_id) != 0) { errno = EINVAL; return -1; }
    /* Ensure tasks/ root exists. */
    char root[MAX_PATHBUF];
    if (tasks_root(agent, root, sizeof(root)) != 0) return -1;
    if (ensure_dir(root, 0700) != 0) return -1;

    /* Create the per-task dir. */
    char dir[MAX_PATHBUF];
    if (task_dir(agent, task_id, dir, sizeof(dir)) != 0) return -1;
    /* Never reopen and overwrite an existing task. */
    if (mkdir(dir, 0700) != 0) return -1;

    /* Sub-dirs. */
    char sub[MAX_PATHBUF];
    if (task_leaf_path(agent, task_id, "artifacts", sub, sizeof(sub)) != 0) return -1;
    (void)mkdir(sub, 0700);
    if (task_leaf_path(agent, task_id, "checkpoints", sub, sizeof(sub)) != 0) return -1;
    (void)mkdir(sub, 0700);

    /* Metadata files. */
    char ts_buf[64];
    int tl = write_iso_now(ts_buf, sizeof(ts_buf));
    if (tl <= 0) return -1;

    char path[MAX_PATHBUF];
    if (task_leaf_path(agent, task_id, "created_at", path, sizeof(path)) != 0) return -1;
    if (atomic_write_file(path, ts_buf, (size_t)tl, 0600) != 0) return -1;
    if (task_leaf_path(agent, task_id, "updated_at", path, sizeof(path)) != 0) return -1;
    if (atomic_write_file(path, ts_buf, (size_t)tl, 0600) != 0) return -1;

    write_text_line(agent, task_id, "verb",   verb ? verb : "");
    write_text_line(agent, task_id, "sender", sender ? sender : "-");

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%ld", (long)sender_pid);
    write_text_line(agent, task_id, "sender_pid", tmp);
    snprintf(tmp, sizeof(tmp), "%ld", (long)sender_uid);
    write_text_line(agent, task_id, "sender_uid", tmp);

    if (reply_to && *reply_to)
        write_text_line(agent, task_id, "reply_to", reply_to);
    if (incoming_task_id && *incoming_task_id)
        write_text_line(agent, task_id, "incoming_task_id", incoming_task_id);

    /* Payload bytes — raw, no newline. */
    if (payload && payload_len > 0) {
        if (task_leaf_path(agent, task_id, "payload", path, sizeof(path)) != 0) return -1;
        if (atomic_write_file(path, payload, payload_len, 0600) != 0) return -1;
    }

    if (task_set_state(agent, task_id, TASK_QUEUED) != 0) return -1;
    if (task_set_status(agent, task_id, "queued") != 0) return -1;
    task_append_event(agent, task_id, "created verb=%s sender=%s",
                      verb ? verb : "?", sender ? sender : "-");
    return 0;
}

int task_set_state(const char *agent, const char *task_id, task_state_t s)
{
    if (write_text_line(agent, task_id, "state", task_state_name(s)) != 0)
        return -1;
    char ts_buf[64];
    int tl = write_iso_now(ts_buf, sizeof(ts_buf));
    if (tl > 0) {
        char path[MAX_PATHBUF];
        if (task_leaf_path(agent, task_id, "updated_at", path, sizeof(path)) == 0)
            atomic_write_file(path, ts_buf, (size_t)tl, 0600);
    }
    return 0;
}

int task_set_status(const char *agent, const char *task_id, const char *status)
{
    return write_text_line(agent, task_id, "status", status);
}

int task_append_event(const char *agent, const char *task_id,
                      const char *fmt, ...)
{
    char path[MAX_PATHBUF];
    if (task_leaf_path(agent, task_id, "events.log", path, sizeof(path)) != 0)
        return -1;
    char line[512];
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    int p = snprintf(line, sizeof(line),
                     "%04d-%02d-%02dT%02d:%02d:%02dZ ",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (p < 0) return -1;
    va_list ap;
    va_start(ap, fmt);
    int q = vsnprintf(line + p, sizeof(line) - (size_t)p, fmt, ap);
    va_end(ap);
    if (q < 0) return -1;
    size_t total = (size_t)p + (size_t)q;
    if (total >= sizeof(line) - 1) total = sizeof(line) - 2;
    line[total] = '\n';
    return append_file(path, line, total + 1, 0600);
}

int task_read_state(const char *agent, const char *task_id, task_state_t *out)
{
    char buf[64];
    if (task_read_string(agent, task_id, "state", buf, sizeof(buf)) != 0)
        return -1;
    /* trim newline */
    size_t l = strlen(buf);
    while (l > 0 && (buf[l-1] == '\n' || buf[l-1] == ' ')) buf[--l] = '\0';
    return parse_state(buf, out);
}

int task_read_string(const char *agent, const char *task_id,
                     const char *leaf, char *out, size_t n)
{
    char path[MAX_PATHBUF];
    if (task_leaf_path(agent, task_id, leaf, path, sizeof(path)) != 0) return -1;
    return read_small_file(path, out, n, NULL);
}

/* ---------- iteration ---------- */

static int cmp_str_(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

void task_iterate(const char *agent, task_iter_cb cb, void *ud)
{
    char root[MAX_PATHBUF];
    if (tasks_root(agent, root, sizeof(root)) != 0) return;
    DIR *d = opendir(root);
    if (!d) return;

    /* Collect names into a bounded list. */
    enum { CAP = 256 };
    char *names[CAP];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < CAP) {
        if (task_validate_id(e->d_name) != 0) continue;
        size_t l = strlen(e->d_name);
        names[n] = malloc(l + 1);
        if (!names[n]) break;
        memcpy(names[n], e->d_name, l + 1);
        n++;
    }
    closedir(d);
    qsort(names, (size_t)n, sizeof(names[0]), cmp_str_);
    for (int i = 0; i < n; i++) {
        cb(names[i], ud);
        free(names[i]);
    }
}

/* ---------- counts ---------- */

static void inc_total_(const char *id, void *ud)
{
    (void)id;
    (*(int *)ud)++;
}

int task_count_total(const char *agent)
{
    int n = 0;
    task_iterate(agent, inc_total_, &n);
    return n;
}

struct active_ctx { const char *agent; int n; };
static void inc_active_(const char *id, void *ud)
{
    struct active_ctx *c = ud;
    task_state_t st;
    if (task_read_state(c->agent, id, &st) != 0) return;
    if (st == TASK_QUEUED || st == TASK_RUNNING || st == TASK_DELEGATED)
        c->n++;
}

int task_count_active(const char *agent)
{
    struct active_ctx c = { agent, 0 };
    task_iterate(agent, inc_active_, &c);
    return c.n;
}

/* ---------- recovery ---------- */

struct recover_ctx { const char *agent; int n; };
static void recover_one_(const char *id, void *ud)
{
    struct recover_ctx *c = ud;
    task_state_t st;
    if (task_read_state(c->agent, id, &st) != 0) return;
    if (st == TASK_QUEUED || st == TASK_RUNNING || st == TASK_DELEGATED) {
        task_set_state(c->agent, id, TASK_FAILED);
        task_set_status(c->agent, id, "failed: interrupted by restart");
        task_append_event(c->agent, id, "recovery: interrupted");
        c->n++;
    }
}

int task_recover_interrupted(const char *agent)
{
    struct recover_ctx c = { agent, 0 };
    task_iterate(agent, recover_one_, &c);
    return c.n;
}

/* ---------- artifact writes ---------- */

static void timestamp_filename_(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    if (strftime(out, n, "%Y%m%dT%H%M%SZ", &tm) == 0 && n > 0) out[0] = '\0';
}

int task_write_artifact(const char *agent, const char *task_id,
                        const char *base_filename,
                        const void *buf, size_t n, int policy)
{
    if (task_validate_id(task_id) != 0 ||
        task_validate_artifact_name(base_filename) != 0) {
        errno = EINVAL;
        return -1;
    }
    char path[MAX_PATHBUF];
    char rel[256];

    if (policy == ARTIFACT_OVERWRITE) {
        int w = snprintf(rel, sizeof(rel), "artifacts/%s", base_filename);
        if (w < 0 || (size_t)w >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
        if (task_leaf_path(agent, task_id, rel, path, sizeof(path)) != 0) return -1;
        return atomic_write_file(path, buf, n, 0600);
    }
    if (policy == ARTIFACT_VERSIONED) {
        char stem[128] = ""; char ext[32] = "";
        const char *dot = strrchr(base_filename, '.');
        if (dot && dot != base_filename) {
            size_t sl = (size_t)(dot - base_filename);
            if (sl >= sizeof(stem) || strlen(dot) >= sizeof(ext)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(stem, base_filename, sl);
            stem[sl] = '\0';
            snprintf(ext, sizeof(ext), "%s", dot);
        } else {
            snprintf(stem, sizeof(stem), "%s", base_filename);
        }
        char ts[24];
        timestamp_filename_(ts, sizeof(ts));
        int w = snprintf(rel, sizeof(rel), "artifacts/%s-%s%s", stem, ts, ext);
        if (w < 0 || (size_t)w >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
        if (task_leaf_path(agent, task_id, rel, path, sizeof(path)) != 0) return -1;
        return atomic_write_file(path, buf, n, 0600);
    }
    /* APPEND_ONLY */
    int w = snprintf(rel, sizeof(rel), "artifacts/%s", base_filename);
    if (w < 0 || (size_t)w >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
    if (task_leaf_path(agent, task_id, rel, path, sizeof(path)) != 0) return -1;
    char banner[80];
    char ts[24]; timestamp_filename_(ts, sizeof(ts));
    int bl = snprintf(banner, sizeof(banner), "\n----- %s -----\n", ts);
    if (bl < 0) return -1;
    if (append_file(path, banner, (size_t)bl, 0600) != 0) return -1;
    if (append_file(path, buf, n, 0600) != 0) return -1;
    return 0;
}

/* ---------- pending table ---------- */

static int pending_root(const char *agent, char *out, size_t n)
{
    return agent_path(out, n, agent, "pending");
}

static int pending_path(const char *agent, const char *task_id,
                        const char *downstream, char *out, size_t n)
{
    if (task_validate_id(task_id) != 0 || validate_name(downstream) != 0) {
        errno = EINVAL;
        return -1;
    }
    char root[MAX_PATHBUF];
    if (pending_root(agent, root, sizeof(root)) != 0) return -1;
    int r = snprintf(out, n, "%s/%s.%s", root, task_id, downstream);
    if (r < 0 || (size_t)r >= n) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

int pending_add(const char *agent, const char *task_id, const char *downstream)
{
    char root[MAX_PATHBUF];
    if (pending_root(agent, root, sizeof(root)) != 0) return -1;
    if (ensure_dir(root, 0700) != 0) return -1;
    char path[MAX_PATHBUF];
    if (pending_path(agent, task_id, downstream, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1) return -1;
    char ts_buf[64];
    int tl = write_iso_now(ts_buf, sizeof(ts_buf));
    if (tl > 0) write_all(fd, ts_buf, (size_t)tl);
    close(fd);
    return 0;
}

int pending_remove(const char *agent, const char *task_id, const char *downstream)
{
    char path[MAX_PATHBUF];
    if (pending_path(agent, task_id, downstream, path, sizeof(path)) != 0) return -1;
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return 0;
}

int pending_count_for_task(const char *agent, const char *task_id)
{
    if (task_validate_id(task_id) != 0) { errno = EINVAL; return -1; }
    char root[MAX_PATHBUF];
    if (pending_root(agent, root, sizeof(root)) != 0) return -1;
    DIR *d = opendir(root);
    if (!d) return 0;
    size_t prefix_len = strlen(task_id);
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (strncmp(e->d_name, task_id, prefix_len) == 0 &&
            e->d_name[prefix_len] == '.')
            n++;
    }
    closedir(d);
    return n;
}

/* ---------- checkpoints ---------- */

int task_write_checkpoint(const char *agent, const char *task_id,
                          const char *content, size_t n)
{
    char dir[MAX_PATHBUF];
    if (task_leaf_path(agent, task_id, "checkpoints", dir, sizeof(dir)) != 0)
        return -1;
    if (ensure_dir(dir, 0700) != 0) return -1;

    /* Find next checkpoint-NNNN file. */
    int max_n = 0;
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strncmp(e->d_name, "checkpoint-", 11) == 0) {
                int v = atoi(e->d_name + 11);
                if (v > max_n) max_n = v;
            }
        }
        closedir(d);
    }
    char path[MAX_PATHBUF];
    int r = snprintf(path, sizeof(path), "%s/checkpoint-%04d", dir, max_n + 1);
    if (r < 0 || (size_t)r >= sizeof(path)) { errno = ENAMETOOLONG; return -1; }
    return atomic_write_file(path, content, n, 0600);
}
