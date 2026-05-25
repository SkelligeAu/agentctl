#include "common.h"
#include "enforcement.h"
#include "profiles.h"
#include "tasks.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <libproc.h>
#endif

/* ---------- create ---------- */

static int cmd_create(const char *name, const char *profile)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "create: invalid name\n");
        return 1;
    }
    if (profile && validate_name(profile) != 0) {
        fprintf(stderr, "create: invalid profile name\n");
        return 1;
    }
    if (ensure_dir(AGENT_ROOT, 0700) != 0) {
        fprintf(stderr, "create: cannot prepare %s: %s\n", AGENT_ROOT, strerror(errno));
        return 1;
    }
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) return 1;
    if (mkdir(dir, 0700) != 0) {
        fprintf(stderr, "create: cannot create %s: %s\n", dir, strerror(errno));
        return 1;
    }
    static const char *subdirs[] = { "artifacts", "outbox", NULL };
    for (int i = 0; subdirs[i]; i++) {
        char p[MAX_PATHBUF];
        if (agent_path(p, sizeof(p), name, subdirs[i]) != 0) return 1;
        if (mkdir(p, 0700) != 0) {
            fprintf(stderr, "create: cannot create %s: %s\n", p, strerror(errno));
            return 1;
        }
    }
    static const char *files[] = { "goal", "policy", "limits", "audit.log", NULL };
    for (int i = 0; files[i]; i++) {
        char p[MAX_PATHBUF];
        if (agent_path(p, sizeof(p), name, files[i]) != 0) return 1;
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd == -1) {
            fprintf(stderr, "create: cannot create %s: %s\n", p, strerror(errno));
            return 1;
        }
        close(fd);
    }
    /* The agent.sock UDS is bound by the runtime at start time, not here. */

    /* Write profile pointer (defaults to worker). */
    {
        const char *p = (profile && *profile) ? profile : "worker";
        char prof_path[MAX_PATHBUF];
        if (agent_path(prof_path, sizeof(prof_path), name, "profile") != 0) return 1;
        char prof_line[MAX_NAME + 2];
        int pl = snprintf(prof_line, sizeof(prof_line), "%s\n", p);
        if (pl < 0 || (size_t)pl >= sizeof(prof_line)) return 1;
        if (atomic_write_file(prof_path, prof_line, (size_t)pl, 0600) != 0) {
            fprintf(stderr, "create: write profile: %s\n", strerror(errno));
            return 1;
        }
    }

    if (write_status(name, "created") != 0) {
        fprintf(stderr, "create: write status: %s\n", strerror(errno));
        return 1;
    }
    audit_log(name, "agent created");
    printf("agent '%s' created at %s\n", name, dir);
    return 0;
}

/* ---------- set-goal ---------- */

static int cmd_set_goal(const char *name, const char *goal)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "goal") != 0) {
        fprintf(stderr, "set-goal: invalid name\n");
        return 1;
    }
    size_t n = strlen(goal);
    char buf[4096];
    if (n + 2 > sizeof(buf)) {
        fprintf(stderr, "set-goal: goal too long (max %zu)\n", sizeof(buf) - 2);
        return 1;
    }
    memcpy(buf, goal, n);
    buf[n] = '\n';
    if (atomic_write_file(path, buf, n + 1, 0600) != 0) {
        fprintf(stderr, "set-goal: %s\n", strerror(errno));
        return 1;
    }
    audit_log(name, "goal set: %.*s", (int)n, goal);
    printf("goal set for %s\n", name);
    return 0;
}

/* ---------- grant / deny ---------- */

static int cap_append(const char *name, const char *kind, const char *cap)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "policy") != 0) {
        fprintf(stderr, "%s: invalid name\n", kind);
        return 1;
    }
    char line[512];
    int r = snprintf(line, sizeof(line), "%s %s\n", kind, cap);
    if (r < 0 || (size_t)r >= sizeof(line)) {
        fprintf(stderr, "%s: capability too long\n", kind);
        return 1;
    }
    if (append_file(path, line, (size_t)r, 0600) != 0) {
        fprintf(stderr, "%s: %s\n", kind, strerror(errno));
        return 1;
    }
    audit_log(name, "%s %s", kind, cap);
    printf("%s %s -> %s\n", kind, cap, name);
    return 0;
}

/* ---------- limits ---------- */
/* apply_limits_from_file lives in common.c now (used by agentd too). */

static int cmd_set_limit(const char *name, const char *kv)
{
    const char *eq = strchr(kv, '=');
    if (!eq || eq == kv) {
        fprintf(stderr, "set-limit: expected KEY=VALUE (e.g. NOFILE=64)\n");
        return 1;
    }
    size_t keylen = (size_t)(eq - kv);

    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "limits") != 0) {
        fprintf(stderr, "set-limit: invalid name\n");
        return 1;
    }

    char old[4096];
    size_t olen = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        ssize_t r = read(fd, old, sizeof(old) - 1);
        close(fd);
        if (r > 0) { olen = (size_t)r; }
    }
    old[olen] = '\0';

    char neu[4096];
    size_t off = 0;
    int replaced = 0;
    char *p = old;
    while (*p) {
        char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        int match = (llen > keylen && p[keylen] == '=' &&
                     memcmp(p, kv, keylen) == 0);
        if (match) {
            int w = snprintf(neu + off, sizeof(neu) - off, "%s\n", kv);
            if (w < 0 || (size_t)w >= sizeof(neu) - off) {
                fprintf(stderr, "set-limit: overflow\n"); return 1;
            }
            off += (size_t)w;
            replaced = 1;
        } else if (llen > 0) {
            if (off + llen + 1 >= sizeof(neu)) {
                fprintf(stderr, "set-limit: overflow\n"); return 1;
            }
            memcpy(neu + off, p, llen);
            off += llen;
            neu[off++] = '\n';
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (!replaced) {
        int w = snprintf(neu + off, sizeof(neu) - off, "%s\n", kv);
        if (w < 0 || (size_t)w >= sizeof(neu) - off) {
            fprintf(stderr, "set-limit: overflow\n"); return 1;
        }
        off += (size_t)w;
    }

    if (atomic_write_file(path, neu, off, 0600) != 0) {
        fprintf(stderr, "set-limit: %s\n", strerror(errno));
        return 1;
    }
    audit_log(name, "limit set: %s", kv);
    printf("limit set: %s (takes effect on next start)\n", kv);
    return 0;
}

/* ---------- start / stop (file-driven; agentd reacts via inotify) ---------- */

/* Is agentd running? Read its pid file under agentctl_root, check liveness. */
static int agentd_is_alive(void)
{
    int fd = open(agentd_pid_path(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) return 0;
    char buf[32];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return 0;
    buf[r] = '\0';
    long p = strtol(buf, NULL, 10);
    if (p <= 0) return 0;
    return run_alive((pid_t)p);
}

/* Poll the agent's status file for up to timeout_ms; return 0 once it flips
 * off "starting"/"created", -1 on timeout. */
static int wait_for_status_flip(const char *name, int timeout_ms)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "status") != 0) return -1;
    int slept = 0;
    while (slept < timeout_ms) {
        char buf[64];
        if (read_small_file(path, buf, sizeof(buf), NULL) == 0) {
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
            if (strcmp(buf, "starting") != 0 &&
                strcmp(buf, "created")  != 0) return 0;
        }
        struct timespec ts = { 0, 50L * 1000L * 1000L };
        nanosleep(&ts, NULL);
        slept += 50;
    }
    return -1;
}

/* Try to send a one-line request to agentd's control socket under
 * agentctl_root and read the single-line response. Returns 0 on success,
 * -1 on connect/io failure, -2 if no daemon is listening. Used by restart
 * and daemon-shutdown — start/stop are file-driven and don't go through
 * here. */
static int agentd_request(const char *cmd_line, char *out_resp, size_t n)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", agentd_sock_path());
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int saved = errno;
        close(fd);
        if (saved == ENOENT || saved == ECONNREFUSED) return -2;
        return -1;
    }
    struct timeval tv = { 5, 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[512];
    int w = snprintf(buf, sizeof(buf), "%s\n", cmd_line);
    if (w < 0 || (size_t)w >= sizeof(buf)) { close(fd); errno = EOVERFLOW; return -1; }
    if (write_all(fd, buf, (size_t)w) == -1) { close(fd); return -1; }
    (void)shutdown(fd, SHUT_WR);
    ssize_t r = read(fd, out_resp, n - 1);
    close(fd);
    if (r <= 0) return -1;
    out_resp[r] = '\0';
    /* trim trailing newline */
    while (r > 0 && (out_resp[r-1] == '\n' || out_resp[r-1] == '\r'))
        out_resp[--r] = '\0';
    return 0;
}

static int cmd_start(const char *name, const char *runtime_path,
                     int fs_override, int sc_override, int cg_override,
                     const char *agentfs_mount)
{
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) {
        fprintf(stderr, "start: invalid name\n");
        return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        fprintf(stderr, "start: agent %s not created (run 'agentctl create %s')\n",
                name, name);
        return 1;
    }
    pid_t old;
    if (read_pid_file(name, &old) == 0 && run_alive(old)) {
        fprintf(stderr, "start: %s already running (pid %ld)\n", name, (long)old);
        return 1;
    }
    char runtime_abs[MAX_PATHBUF];
    if (realpath(runtime_path, runtime_abs) == NULL) {
        fprintf(stderr, "start: realpath '%s': %s\n", runtime_path, strerror(errno));
        return 1;
    }
    if (access(runtime_abs, X_OK) != 0) {
        fprintf(stderr, "start: '%s' not executable: %s\n", runtime_abs, strerror(errno));
        return 1;
    }

    /* Canonical state lives on disk. Always write the trigger files; either
     * agentd will pick the change up via inotify, or — if there's no daemon
     * — we play the role of supervisor ourselves for this one shot. */
    write_agent_setting(name, "exec", runtime_path);
    write_agent_setting(name, "desired_state", "running");

    /* Transport substrate. --agentfs sets/refreshes the transport file;
     * absence keeps whatever's there (or implicit UDS default). */
    if (agentfs_mount && *agentfs_mount) {
        if (transport_write(name, TRANSPORT_AGENTFS, agentfs_mount) != 0) {
            fprintf(stderr, "start: cannot record transport: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    if (agentd_is_alive()) {
        /* Files on disk are canonical. agentd will pick up the desired_state
         * write either via inotify (Linux) or via its periodic scan (macOS).
         * The `kick` over the socket is a best-effort nudge so we don't have
         * to wait for the next poll-timer tick on platforms without inotify. */
        char cmd_buf[256], resp[256];
        snprintf(cmd_buf, sizeof(cmd_buf), "kick %s", name);
        (void)agentd_request(cmd_buf, resp, sizeof(resp));

        if (wait_for_status_flip(name, 3000) != 0) {
            fprintf(stderr,
                    "start: agentd did not bring %s up within 3s\n", name);
            return 1;
        }
        pid_t pid = 0;
        (void)read_pid_file(name, &pid);
        printf("started %s pid=%ld (via agentd)\n", name, (long)pid);
        return 0;
    }

    /* No daemon — run the supervisor inline. No broker in direct mode
     * (there's no long-lived supervisor process to mediate fd transfers). */
    pid_t pid = 0;
    if (spawn_agent_runtime(name, runtime_path, "direct",
                            fs_override, sc_override, cg_override,
                            &pid, NULL) != 0) {
        fprintf(stderr, "start: spawn: %s\n", strerror(errno));
        return 1;
    }
    printf("started %s pid=%ld pgid=%ld (direct; no agentd)\n",
           name, (long)pid, (long)pid);
    return 0;
}

static int cmd_enable(const char *name, int enable)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "%s: invalid name\n", enable ? "enable" : "disable");
        return 1;
    }
    if (write_agent_setting(name, "enabled", enable ? "yes" : "no") != 0) {
        fprintf(stderr, "%s: %s\n", enable ? "enable" : "disable", strerror(errno));
        return 1;
    }
    audit_log(name, "%s requested", enable ? "enable" : "disable");
    printf("%s %s\n", name, enable ? "enabled" : "disabled");
    return 0;
}

static int cmd_set_restart_policy(const char *name, const char *policy)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "set-restart-policy: invalid name\n"); return 1;
    }
    if (strcmp(policy, "never") != 0 && strcmp(policy, "on-failure") != 0 &&
        strcmp(policy, "always") != 0) {
        fprintf(stderr, "set-restart-policy: expected never|on-failure|always\n");
        return 1;
    }
    if (write_agent_setting(name, "restart_policy", policy) != 0) {
        fprintf(stderr, "set-restart-policy: %s\n", strerror(errno)); return 1;
    }
    audit_log(name, "restart_policy=%s", policy);
    printf("restart_policy set to %s\n", policy);
    return 0;
}

static int cmd_restart(const char *name)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "restart: invalid name\n"); return 1;
    }
    char resp[256];
    char cmd_buf[256];
    snprintf(cmd_buf, sizeof(cmd_buf), "restart %s", name);
    int r = agentd_request(cmd_buf, resp, sizeof(resp));
    if (r == 0) {
        puts(resp);
        return (resp[0] == 'O') ? 0 : 1;
    }
    fprintf(stderr, "restart: no agentd running; use 'agentctl stop' + 'start'\n");
    return 1;
}

static int cmd_daemon_shutdown(void)
{
    char resp[256];
    int r = agentd_request("shutdown", resp, sizeof(resp));
    if (r == -2) {
        fprintf(stderr, "no agentd running\n"); return 1;
    }
    if (r != 0) {
        fprintf(stderr, "agentd: %s\n", strerror(errno)); return 1;
    }
    puts(resp);
    return 0;
}

/* ---------- send ---------- */

static int cmd_send(const char *name, const char *verb)
{
    size_t vlen = strlen(verb);
    if (vlen == 0 || vlen >= MAX_VERB) {
        fprintf(stderr, "send: invalid verb\n");
        return 1;
    }
    for (size_t i = 0; i < vlen; i++) {
        unsigned char c = (unsigned char)verb[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) {
            fprintf(stderr, "send: verb has illegal char\n");
            return 1;
        }
    }
    char inbox[MAX_PATHBUF];
    if (agent_path(inbox, sizeof(inbox), name, "inbox") != 0) {
        fprintf(stderr, "send: invalid name\n");
        return 1;
    }
    pid_t pid;
    if (read_pid_file(name, &pid) != 0 || !run_alive(pid)) {
        fprintf(stderr, "send: no live runtime for '%s' — did you 'agentctl start %s'?\n",
                name, name);
        return 1;
    }

    char *payload = malloc(MAX_PAYLOAD);
    if (!payload) {
        fprintf(stderr, "send: out of memory\n");
        return 1;
    }
    size_t total = 0;
    while (total < MAX_PAYLOAD) {
        ssize_t r = read(0, payload + total, MAX_PAYLOAD - total);
        if (r == -1) {
            if (errno == EINTR) continue;
            fprintf(stderr, "send: read stdin: %s\n", strerror(errno));
            free(payload);
            return 1;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    if (total == MAX_PAYLOAD) {
        char extra;
        ssize_t r = read(0, &extra, 1);
        if (r > 0) {
            fprintf(stderr, "send: payload exceeds %u bytes\n", MAX_PAYLOAD);
            free(payload);
            return 1;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);

    int s = send_to_agent(name, verb, payload, total);
    free(payload);
    if (s == -2) {
        fprintf(stderr, "send: no reader on inbox for '%s'\n", name);
        return 1;
    }
    if (s != 0) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return 1;
    }
    audit_log(name, "send verb=%s len=%zu", verb, total);
    printf("sent %s (%zu bytes) to %s\n", verb, total, name);
    return 0;
}

/* ---------- tasks ---------- */

struct tasks_ctx { const char *agent; int header_printed; };

static void tasks_row_(const char *task_id, void *ud)
{
    struct tasks_ctx *c = ud;
    if (!c->header_printed) {
        printf("%-24s %-10s %s\n", "TASK-ID", "STATE", "VERB");
        c->header_printed = 1;
    }
    task_state_t st;
    char state_str[32] = "?";
    if (task_read_state(c->agent, task_id, &st) == 0)
        snprintf(state_str, sizeof(state_str), "%s", task_state_name(st));
    char verb[MAX_VERB] = "";
    if (task_read_string(c->agent, task_id, "verb", verb, sizeof(verb)) == 0) {
        char *nl = strchr(verb, '\n');
        if (nl) *nl = '\0';
    }
    printf("%-24s %-10s %s\n", task_id, state_str, verb[0] ? verb : "-");
}

static int cmd_tasks(const char *name)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "tasks: invalid name\n"); return 1;
    }
    struct tasks_ctx c = { name, 0 };
    task_iterate(name, tasks_row_, &c);
    if (!c.header_printed) printf("(no tasks)\n");
    return 0;
}

static void trim_nl_(char *s)
{
    size_t l = strlen(s);
    while (l > 0 && (s[l-1] == '\n' || s[l-1] == '\r')) s[--l] = '\0';
}

static int cmd_task(const char *name, const char *task_id)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "task: invalid agent name\n"); return 1;
    }
    char buf[4096];
    char path[MAX_PATHBUF];

    /* Existence check via state file. */
    if (task_read_string(name, task_id, "state", buf, sizeof(buf)) != 0) {
        fprintf(stderr, "task: no such task '%s' for agent '%s'\n",
                task_id, name);
        return 1;
    }
    trim_nl_(buf);
    printf("task:       %s\n", task_id);
    printf("agent:      %s\n", name);
    printf("state:      %s\n", buf);

    static const char *fields[] = { "status", "verb", "sender",
                                    "sender_pid", "sender_uid",
                                    "reply_to", "incoming_task_id",
                                    "created_at", "updated_at", NULL };
    for (int i = 0; fields[i]; i++) {
        if (task_read_string(name, task_id, fields[i], buf, sizeof(buf)) != 0)
            continue;
        trim_nl_(buf);
        if (buf[0] != '\0') printf("%-10s  %s\n", fields[i], buf);
    }

    /* Artifacts list */
    {
        char rel[256];
        snprintf(rel, sizeof(rel), "tasks/%s/artifacts", task_id);
        if (agent_path(path, sizeof(path), name, rel) == 0) {
            DIR *d = opendir(path);
            if (d) {
                int printed = 0;
                struct dirent *e;
                while ((e = readdir(d)) != NULL) {
                    if (e->d_name[0] == '.') continue;
                    char fp[MAX_PATHBUF];
                    snprintf(fp, sizeof(fp), "%s/%s", path, e->d_name);
                    struct stat st;
                    if (stat(fp, &st) != 0) continue;
                    if (!printed) { printf("artifacts:\n"); printed = 1; }
                    printf("  %8lld  %s\n", (long long)st.st_size, e->d_name);
                }
                closedir(d);
            }
        }
    }

    /* Result file */
    {
        char rel[64];
        snprintf(rel, sizeof(rel), "tasks/%s/result", task_id);
        if (agent_path(path, sizeof(path), name, rel) == 0 &&
            read_small_file(path, buf, sizeof(buf), NULL) == 0 && buf[0]) {
            printf("result:\n");
            fputs(buf, stdout);
            if (buf[strlen(buf) - 1] != '\n') fputc('\n', stdout);
        }
    }

    /* Events (last 20 lines via re-use of print_tail logic — inlined here) */
    {
        char rel[64];
        snprintf(rel, sizeof(rel), "tasks/%s/events.log", task_id);
        if (agent_path(path, sizeof(path), name, rel) == 0) {
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd != -1) {
                struct stat st;
                if (fstat(fd, &st) == 0 && st.st_size > 0) {
                    size_t sz = (size_t)st.st_size;
                    if (sz > 64 * 1024) sz = 64 * 1024;
                    char *eb = malloc(sz + 1);
                    if (eb) {
                        ssize_t r = read_all(fd, eb, sz);
                        if (r > 0) {
                            eb[r] = '\0';
                            printf("events (last 20):\n");
                            /* tail 20 lines */
                            size_t pos = (size_t)r, found = 0;
                            while (pos > 0) {
                                pos--;
                                if (eb[pos] == '\n') {
                                    found++;
                                    if (found > 20) { pos++; break; }
                                }
                            }
                            fwrite(eb + pos, 1, (size_t)r - pos, stdout);
                        }
                        free(eb);
                    }
                }
                close(fd);
            }
        }
    }
    return 0;
}

/* ---------- profiles / config ---------- */

static void profile_print_row(const char *profile_name, void *ud)
{
    int *first = (int *)ud;
    if (!*first) { printf("%-16s %s\n", "PROFILE", "PATH"); *first = 1; }
    char path[MAX_PATHBUF];
    if (profile_locate(profile_name, path, sizeof(path)) == 0)
        printf("%-16s %s\n", profile_name, path);
    else
        printf("%-16s (not found)\n", profile_name);
}

static int cmd_profiles(void)
{
    int first = 0;
    profile_list(profile_print_row, &first);
    if (!first) {
        fputs("no profile files found in any of:\n", stderr);
        fputs("  $AGENT_PROFILES_DIR (if set)\n", stderr);
        fputs("  /usr/lib/agents/profiles\n", stderr);
        fputs("  /usr/local/lib/agents/profiles\n", stderr);
        fputs("  ./profiles\n", stderr);
        return 1;
    }
    return 0;
}

static int cmd_show_profile(const char *profile_name)
{
    if (validate_name(profile_name) != 0) {
        fprintf(stderr, "show-profile: invalid name\n"); return 1;
    }
    char path[MAX_PATHBUF];
    if (profile_locate(profile_name, path, sizeof(path)) != 0) {
        fprintf(stderr, "show-profile: '%s' not found\n", profile_name);
        return 1;
    }
    profile_cfg_t cfg;
    if (profile_load_by_name(profile_name, &cfg) != 0) {
        fprintf(stderr, "show-profile: load: %s\n", strerror(errno)); return 1;
    }
    printf("profile:         %s\n", cfg.profile_name);
    printf("source:          %s\n", path);
    printf("dispatch:        %s\n", dispatch_name(cfg.dispatch));
    printf("artifact_policy: %s\n", artifact_policy_name(cfg.artifact_policy));
    printf("idle_timeout:    %d\n", cfg.idle_timeout_sec);
    printf("---- raw ----\n");
    fputs(cfg.raw, stdout);
    return 0;
}

static int cmd_set_profile(const char *name, const char *profile_name)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "set-profile: invalid agent name\n"); return 1;
    }
    if (validate_name(profile_name) != 0) {
        fprintf(stderr, "set-profile: invalid profile name\n"); return 1;
    }
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "profile") != 0) return 1;
    char line[MAX_NAME + 2];
    int l = snprintf(line, sizeof(line), "%s\n", profile_name);
    if (l < 0 || (size_t)l >= sizeof(line)) return 1;
    if (atomic_write_file(path, line, (size_t)l, 0600) != 0) {
        fprintf(stderr, "set-profile: %s\n", strerror(errno)); return 1;
    }
    audit_log(name, "profile set to %s (takes effect on next start)", profile_name);
    printf("profile set to %s (takes effect on next start)\n", profile_name);
    return 0;
}

static int cmd_config(const char *name, const char *kv)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "config: invalid agent name\n"); return 1;
    }
    if (!strchr(kv, '=')) {
        fprintf(stderr, "config: expected KEY=VALUE\n"); return 1;
    }
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "config") != 0) return 1;
    if (kv_file_set(path, kv) != 0) {
        fprintf(stderr, "config: %s\n", strerror(errno)); return 1;
    }
    audit_log(name, "config set: %s", kv);
    printf("config set: %s (takes effect on next start)\n", kv);
    return 0;
}

/* ---------- ping ---------- */

static int cmd_ping(const char *name)
{
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) {
        fprintf(stderr, "ping: invalid name\n");
        return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        fprintf(stderr, "ping: no agent at %s\n", dir);
        return 1;
    }

    /* On agentfs there is no per-message reverse channel from the kernel
     * mailbox, so ping is fire-and-forget. We measure the write latency
     * and print which substrate carried it. */
    transport_cfg_t tcfg;
    transport_resolve(name, &tcfg);
    if (tcfg.kind == TRANSPORT_AGENTFS) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int s = agentfs_send(tcfg.mount, name, "ping", NULL, NULL, NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt_ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                       (double)(t1.tv_nsec - t0.tv_nsec) / 1.0e6;
        if (s == 0) {
            printf("agent=%s transport=agentfs send=%.2fms (no reply over agentfs)\n",
                   name, dt_ms);
            return 0;
        }
        if (s == -2) {
            fprintf(stderr, "ping: no inbox at %s/agents/%s/inbox\n",
                    tcfg.mount, name);
            return 1;
        }
        fprintf(stderr, "ping: %s\n", strerror(errno));
        return 1;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int fd = connect_agent(name);
    if (fd == -2) {
        fprintf(stderr, "ping: no live runtime for '%s'\n", name);
        return 1;
    }
    if (fd == -1) {
        fprintf(stderr, "ping: connect: %s\n", strerror(errno));
        return 1;
    }

    /* peer credentials of the server, as the kernel sees it from our side */
    peer_id_t peer;
    if (get_peer_creds(fd, &peer) != 0) memset(&peer, 0, sizeof(peer));

    if (send_framed_message(fd, "ping", NULL, 0) != 0) {
        fprintf(stderr, "ping: send: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    struct timeval tv = { 5, 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char reply[128];
    ssize_t n;
    do { n = read(fd, reply, sizeof(reply) - 1); } while (n == -1 && errno == EINTR);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(fd);

    double rtt_ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                    (double)(t1.tv_nsec - t0.tv_nsec) / 1.0e6;

    if (n > 0) {
        reply[n] = '\0';
        char *nl = strchr(reply, '\n');
        if (nl) *nl = '\0';
        printf("agent=%s pid=%ld uid=%ld rtt=%.2fms reply=\"%s\"\n",
               name, (long)peer.pid, (long)peer.uid, rtt_ms, reply);
    } else {
        printf("agent=%s pid=%ld uid=%ld rtt=%.2fms (no reply)\n",
               name, (long)peer.pid, (long)peer.uid, rtt_ms);
    }
    return 0;
}

/* ---------- stop / kill / list ---------- */

/* Recursive rmdir. Refuses to follow symlinks. */
static int remove_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) {
        if (errno == ENOTDIR || errno == ENOENT) return unlink(path);
        return -1;
    }
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char p[MAX_PATHBUF];
        if (snprintf(p, sizeof(p), "%s/%s", path, e->d_name) >= (int)sizeof(p)) {
            rc = -1; continue;
        }
        struct stat st;
        if (lstat(p, &st) != 0) { rc = -1; continue; }
        if (S_ISDIR(st.st_mode)) {
            if (remove_tree(p) != 0) rc = -1;
        } else {
            if (unlink(p) != 0) rc = -1;
        }
    }
    closedir(d);
    if (rmdir(path) != 0) rc = -1;
    return rc;
}

/* Poll until the process is gone, or total_ms elapses.
 * If `pidfd` >= 0, use pidfd_send_signal(pidfd, 0) for race-free liveness;
 * otherwise fall back to kill(pid, 0). Returns 0 if gone, -1 on timeout. */
static int wait_pid_gone(pid_t pid, int pidfd, int total_ms)
{
    if (pidfd >= 0) {
        int r = lifecycle_pidfd_alive(pidfd);
        if (r == 0) return 0;
        /* r > 0 → still alive; r < 0 → unexpected error, fall through. */
    }
    if (pid <= 0 || !run_alive(pid)) return 0;
    int slept = 0;
    const int step_ms = 50;
    while (slept < total_ms) {
        struct timespec ts = { 0, (long)step_ms * 1000L * 1000L };
        nanosleep(&ts, NULL);
        slept += step_ms;
        if (pidfd >= 0) {
            int r = lifecycle_pidfd_alive(pidfd);
            if (r == 0) return 0;
            if (r > 0) continue;
            /* r < 0: fall through to the legacy probe. */
        }
        if (!run_alive(pid)) return 0;
    }
    return -1;
}

static int cmd_stop(const char *name)
{
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) {
        fprintf(stderr, "stop: invalid name\n");
        return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        fprintf(stderr, "stop: no agent at %s\n", dir);
        return 1;
    }

    /* Canonical intent on disk. agentd will catch this via inotify and
     * SIGTERM the runtime; if there's no daemon, we signal directly below. */
    write_agent_setting(name, "desired_state", "stopped");

    pid_t pid = -1;
    int have_pid = (read_pid_file(name, &pid) == 0);

    if (have_pid && run_alive(pid)) {
        int pidfd = -1;       /* lazy: only opened in the direct path */
        int via_pidfd = 0;
        if (agentd_is_alive()) {
            /* Nudge agentd to reconcile right now (rather than waiting for
             * its periodic scan on platforms without inotify). agentd holds
             * the authoritative pidfd for its own children. */
            char cmd_buf[256], resp[256];
            snprintf(cmd_buf, sizeof(cmd_buf), "kick %s", name);
            (void)agentd_request(cmd_buf, resp, sizeof(resp));
        } else {
            /* Direct mode (no supervisor). Lazily acquire a pidfd so signal
             * delivery is race-free against PID reuse after this point.
             * Caveat: this does NOT eliminate the pre-open race window —
             * the pid we just read from disk could already have been
             * reused. Direct mode remains best-effort; agentd-supervised
             * mode is the production lifecycle path. */
            pidfd = lifecycle_pidfd_open(pid);
            via_pidfd = (pidfd >= 0);
            int sig_rc = via_pidfd
                            ? lifecycle_pidfd_signal(pidfd, SIGTERM)
                            : kill(pid, SIGTERM);
            if (sig_rc == -1 && errno != ESRCH) {
                fprintf(stderr, "stop: %s: %s\n",
                        via_pidfd ? "pidfd_send_signal" : "kill",
                        strerror(errno));
                if (pidfd >= 0) close(pidfd);
                return 1;
            }
            /* Also signal the process group to catch any forked children.
             * pgid is reuse-prone; cgroup.kill is the planned upgrade for
             * cgroup-active profiles. */
            (void)lifecycle_signal_group(pid, SIGTERM);
        }
        if (wait_pid_gone(pid, pidfd, 2000) != 0) {
            fprintf(stderr,
                    "stop: pid %ld still running after 2s; try 'agentctl kill %s'\n",
                    (long)pid, name);
            if (pidfd >= 0) close(pidfd);
            return 1;
        }
        if (pidfd >= 0) close(pidfd);
        printf("stopped %s (pid %ld)%s\n", name, (long)pid,
               agentd_is_alive() ? " (via agentd)"
                                 : (via_pidfd ? " (direct, pidfd)" : " (direct)"));
    } else {
        printf("stopped %s (no live process)\n", name);
    }

    if (remove_tree(dir) != 0) {
        fprintf(stderr, "stop: cleanup %s: %s\n", dir, strerror(errno));
        return 1;
    }
    printf("removed %s\n", dir);
    return 0;
}

static int cmd_kill(const char *name)
{
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) {
        fprintf(stderr, "kill: invalid name\n");
        return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        fprintf(stderr, "kill: no agent at %s\n", dir);
        return 1;
    }
    pid_t pid = -1;
    int have_pid = (read_pid_file(name, &pid) == 0);
    if (have_pid && run_alive(pid)) {
        /* Prefer cgroup.kill (atomic subtree SIGKILL) when the profile has
         * cgroup ownership and the cgroup is reachable. Falls back to
         * pidfd+killpg otherwise. */
        enforcement_state_t es;
        int used_cgroup = 0;
        if (enforcement_read_state(name, &es) == 0 &&
            es.cgroup_status == ENF_STATUS_ACTIVE && es.cgroup_path[0]) {
            if (lifecycle_cgroup_kill(es.cgroup_path) == 0) {
                used_cgroup = 1;
            }
        }
        int pidfd = -1;
        int via_pidfd = 0;
        if (!used_cgroup) {
            /* Same lazy-pidfd pattern as cmd_stop; see caveat there. */
            pidfd = lifecycle_pidfd_open(pid);
            via_pidfd = (pidfd >= 0);
            int sig_rc = via_pidfd
                            ? lifecycle_pidfd_signal(pidfd, SIGKILL)
                            : kill(pid, SIGKILL);
            if (sig_rc == -1 && errno != ESRCH) {
                fprintf(stderr, "kill: %s: %s\n",
                        via_pidfd ? "pidfd_send_signal" : "kill",
                        strerror(errno));
                if (pidfd >= 0) close(pidfd);
                return 1;
            }
            (void)lifecycle_signal_group(pid, SIGKILL);
        }
        wait_pid_gone(pid, pidfd, 500);
        if (pidfd >= 0) close(pidfd);
        printf("killed %s (pid %ld)%s\n", name, (long)pid,
               used_cgroup ? " (cgroup.kill)" :
               (via_pidfd  ? " (pidfd)"        : ""));
    } else {
        printf("killed %s (no live process)\n", name);
    }
    if (remove_tree(dir) != 0) {
        fprintf(stderr, "kill: cleanup %s: %s\n", dir, strerror(errno));
        return 1;
    }
    printf("removed %s\n", dir);
    return 0;
}

static int cmd_list(void)
{
    DIR *d = opendir(AGENT_ROOT);
    if (!d) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "list: %s: %s\n", AGENT_ROOT, strerror(errno));
        return 1;
    }
    int printed_header = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (validate_name(e->d_name) != 0) continue;
        char dir[MAX_PATHBUF];
        if (snprintf(dir, sizeof(dir), "%s/%s", AGENT_ROOT, e->d_name) >= (int)sizeof(dir))
            continue;
        struct stat st;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        char buf[256];
        char status[32] = "?";
        char path[MAX_PATHBUF];
        if (agent_path(path, sizeof(path), e->d_name, "status") == 0 &&
            read_small_file(path, buf, sizeof(buf), NULL) == 0) {
            size_t i = 0;
            while (i < sizeof(status) - 1 && buf[i] && buf[i] != '\n') {
                status[i] = buf[i]; i++;
            }
            status[i] = '\0';
        }
        pid_t pid = 0;
        char pid_str[16] = "-";
        int alive = 0;
        if (read_pid_file(e->d_name, &pid) == 0) {
            snprintf(pid_str, sizeof(pid_str), "%ld", (long)pid);
            alive = run_alive(pid);
        }
        if (!printed_header) {
            printf("%-24s %-12s %-8s %-5s\n", "NAME", "STATUS", "PID", "ALIVE");
            printed_header = 1;
        }
        printf("%-24s %-12s %-8s %-5s\n",
               e->d_name, status, pid_str, alive ? "yes" : "no");
    }
    closedir(d);
    if (!printed_header) printf("(no agents)\n");
    return 0;
}

/* ---------- inspect ---------- */

static void print_tail(const char *path, size_t lines)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return;
    struct stat st;
    if (fstat(fd, &st) == -1) { close(fd); return; }
    size_t sz = (size_t)st.st_size;
    if (sz == 0) { close(fd); return; }
    if (sz > (1u << 20)) sz = (1u << 20);
    char *buf = malloc(sz + 1);
    if (!buf) { close(fd); return; }
    ssize_t r = read_all(fd, buf, sz);
    close(fd);
    if (r <= 0) { free(buf); return; }
    buf[r] = '\0';
    size_t pos = (size_t)r;
    size_t found = 0;
    while (pos > 0) {
        pos--;
        if (buf[pos] == '\n') {
            found++;
            if (found > lines) { pos++; break; }
        }
    }
    fwrite(buf + pos, 1, (size_t)r - pos, stdout);
    free(buf);
}

#if defined(__linux__)
static void print_proc_info(pid_t pid)
{
    char p[64];
    snprintf(p, sizeof(p), "/proc/%ld/status", (long)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd == -1) { printf("  (unavailable)\n"); return; }
    char buf[4096];
    ssize_t r = read_all(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return;
    buf[r] = '\0';
    static const char *keys[] = { "State:", "VmRSS:", "Threads:", NULL };
    for (int k = 0; keys[k]; k++) {
        const char *line = strstr(buf, keys[k]);
        if (line) {
            const char *eol = strchr(line, '\n');
            if (eol) printf("  %.*s\n", (int)(eol - line), line);
        }
    }
}
#elif defined(__APPLE__)
static void print_proc_info(pid_t pid)
{
    struct proc_taskinfo ti;
    int r = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti));
    if (r != (int)sizeof(ti)) { printf("  (unavailable)\n"); return; }
    printf("  VmRSS:   %llu kB\n", (unsigned long long)(ti.pti_resident_size / 1024));
    printf("  Threads: %u\n", ti.pti_threadnum);
}
#else
static void print_proc_info(pid_t pid) { (void)pid; printf("  (unavailable)\n"); }
#endif

static void print_caps_indented(const char *buf)
{
    const char *p = buf;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len > 0) printf("  %.*s\n", (int)len, p);
        if (!eol) break;
        p = eol + 1;
    }
}

static int cmd_inspect(const char *name)
{
    char dir[MAX_PATHBUF], path[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) {
        fprintf(stderr, "inspect: invalid name\n");
        return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        fprintf(stderr, "inspect: no agent at %s\n", dir);
        return 1;
    }
    printf("agent:  %s\n", name);
    printf("dir:    %s\n", dir);

    pid_t pid = -1;
    if (read_pid_file(name, &pid) == 0) {
        printf("pid:    %ld (%s)\n", (long)pid, run_alive(pid) ? "alive" : "dead");
    } else {
        printf("pid:    <none>\n");
    }

    {
        profile_cfg_t cfg;
        if (profile_load_for_agent(name, &cfg) == 0) {
            printf("profile: %s (dispatch=%s artifact_policy=%s idle_timeout=%d)\n",
                   cfg.profile_name, dispatch_name(cfg.dispatch),
                   artifact_policy_name(cfg.artifact_policy),
                   cfg.idle_timeout_sec);
        }
    }

    {
        enforcement_state_t es;
        if (enforcement_read_state(name, &es) == 0) {
            printf("enforcement:\n");
            printf("  landlock: %s (rules=%d)\n",
                   enforce_status_word(es.landlock_status), es.landlock_rules);
            printf("  seccomp:  %s\n", enforce_status_word(es.seccomp_status));
            printf("  cgroup:   %s\n", enforce_status_word(es.cgroup_status));
            if (es.cgroup_path[0]) printf("  cgroup_path: %s\n", es.cgroup_path);
            if (es.reason[0])      printf("  reason:      %s\n", es.reason);
        }
    }

    {
        transport_cfg_t tcfg;
        if (transport_resolve(name, &tcfg) == 0) {
            printf("transport: %s", transport_name(tcfg.kind));
            if (tcfg.kind == TRANSPORT_AGENTFS) printf(" mount=%s", tcfg.mount);
            printf("\n");
        }
    }

    {
        char sup[64] = "-";
        char desired[64] = "-";
        char restart_policy[64] = "on-failure";
        char restart_count[32] = "0";
        char enabled[8] = "yes";
        (void)read_agent_setting(name, "supervisor",     sup, sizeof(sup));
        (void)read_agent_setting(name, "desired_state",  desired, sizeof(desired));
        (void)read_agent_setting(name, "restart_policy", restart_policy, sizeof(restart_policy));
        (void)read_agent_setting(name, "restart_count",  restart_count, sizeof(restart_count));
        (void)read_agent_setting(name, "enabled",        enabled, sizeof(enabled));

        char status_word[64] = "-";
        char sbuf[128];
        if (agent_path(path, sizeof(path), name, "status") == 0 &&
            read_small_file(path, sbuf, sizeof(sbuf), NULL) == 0) {
            size_t l = strlen(sbuf);
            while (l > 0 && (sbuf[l-1] == '\n' || sbuf[l-1] == ' ')) sbuf[--l] = '\0';
            snprintf(status_word, sizeof(status_word), "%s", sbuf);
        }
        printf("supervisor:\n");
        printf("  mode=%s\n", sup);
        printf("  enabled=%s\n", enabled);
        printf("  desired_state=%s\n", desired);
        printf("  actual_state=%s\n", status_word);
        printf("  restart_policy=%s\n", restart_policy);
        printf("  restart_count=%s\n", restart_count);
    }

    char buf[4096];
    if (agent_path(path, sizeof(path), name, "status") == 0 &&
        read_small_file(path, buf, sizeof(buf), NULL) == 0) {
        size_t l = strlen(buf);
        while (l > 0 && (buf[l - 1] == '\n' || buf[l - 1] == ' ')) buf[--l] = '\0';
        printf("status: %s\n", buf);
    }
    if (agent_path(path, sizeof(path), name, "goal") == 0 &&
        read_small_file(path, buf, sizeof(buf), NULL) == 0) {
        size_t l = strlen(buf);
        while (l > 0 && buf[l - 1] == '\n') buf[--l] = '\0';
        printf("goal:   %s\n", buf);
    }
    if (agent_path(path, sizeof(path), name, "policy") == 0 &&
        read_small_file(path, buf, sizeof(buf), NULL) == 0 && buf[0] != '\0') {
        printf("policy:\n");
        print_caps_indented(buf);
    }
    if (agent_path(path, sizeof(path), name, "limits") == 0 &&
        read_small_file(path, buf, sizeof(buf), NULL) == 0 && buf[0] != '\0') {
        printf("limits:\n");
        print_caps_indented(buf);
    }
    if (pid > 0 && run_alive(pid)) {
        printf("proc:\n");
        print_proc_info(pid);
    }
    printf("audit (last %d):\n", AUDIT_TAIL_LINES);
    if (agent_path(path, sizeof(path), name, "audit.log") == 0) {
        print_tail(path, AUDIT_TAIL_LINES);
    }
    return 0;
}

/* ---------- logs ---------- */

static int cmd_logs(const char *name)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "audit.log") != 0) {
        fprintf(stderr, "logs: invalid name\n");
        return 1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) { fprintf(stderr, "logs: %s\n", strerror(errno)); return 1; }
    char buf[4096];
    ssize_t r;
    int rc = 0;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        if (write_all(1, buf, (size_t)r) == -1) { rc = 1; break; }
    }
    if (r == -1) rc = 1;
    close(fd);
    return rc;
}

/* ---------- artifacts ---------- */

struct artifacts_ctx { const char *agent; int header_printed; };

static void artifacts_for_task_(const char *task_id, void *ud)
{
    struct artifacts_ctx *c = ud;
    char dir[MAX_PATHBUF];
    char rel[64];
    snprintf(rel, sizeof(rel), "tasks/%s/artifacts", task_id);
    if (agent_path(dir, sizeof(dir), c->agent, rel) != 0) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char p[MAX_PATHBUF];
        if (snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >= (int)sizeof(p))
            continue;
        struct stat st;
        if (stat(p, &st) != 0) continue;
        if (!c->header_printed) {
            printf("%-24s %9s  %s\n", "TASK-ID", "BYTES", "FILE");
            c->header_printed = 1;
        }
        printf("%-24s %9lld  %s\n", task_id, (long long)st.st_size, e->d_name);
    }
    closedir(d);
}

static int cmd_artifacts(const char *name)
{
    if (validate_name(name) != 0) {
        fprintf(stderr, "artifacts: invalid name\n");
        return 1;
    }
    struct artifacts_ctx c = { name, 0 };
    task_iterate(name, artifacts_for_task_, &c);
    if (!c.header_printed) printf("(no artifacts)\n");
    return 0;
}

/* ---------- dispatch ---------- */

static void usage(void)
{
    fputs(
        "usage: agentctl <command> [args]\n"
        "  create        <name> [--profile <p>]\n"
        "  set-goal      <name> \"<goal>\"\n"
        "  grant         <name> <capability>\n"
        "  deny          <name> <capability>\n"
        "  set-limit     <name> KEY=VALUE     (CPU|AS|NOFILE|FSIZE; via setrlimit)\n"
        "  set-profile   <name> <profile>     (writes <root>/agents/<name>/profile)\n"
        "  config        <name> KEY=VALUE     (per-agent override; KEYs as in profile)\n"
        "  profiles                            (list available profiles)\n"
        "  show-profile  <profile>             (print effective profile contents)\n"
        "  start         <name> --exec <path>\n"
        "                  [--enforce-fs|--no-enforce-fs]\n"
        "                  [--seccomp minimal|off]\n"
        "                  [--cgroup|--no-cgroup]\n"
        "                  [--agentfs <mountpoint>]   # use kernel mailbox\n"
        "  send          <name> <verb>         (UDS, reads stdin)\n"
        "  ping          <name>                (UDS, prints authenticated peer + RTT)\n"
        "  list                                (all agents under the data root)\n"
        "  inspect       <name>\n"
        "  logs          <name>\n"
        "  artifacts     <name>                (across all tasks)\n"
        "  tasks         <name>                (list this agent's tasks)\n"
        "  task          <name> <task-id>      (detailed task inspection)\n"
        "  stop          <name>                (SIGTERM, wait, remove dir)\n"
        "  kill          <name>                (SIGKILL, remove dir)\n"
        "  restart       <name>                (via agentd; same fork lineage)\n"
        "  enable        <name>                (agentd will keep it running)\n"
        "  disable       <name>                (agentd will stop it)\n"
        "  set-restart-policy <name> <p>       (never|on-failure|always)\n"
        "  daemon-shutdown                     (tell agentd to exit)\n",
        stderr);
}

int main(int argc, char **argv)
{
    if (refuse_root() != 0) return 1;
    if (argc < 2) { usage(); return 2; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "create") == 0) {
        const char *agent_name = NULL;
        const char *profile = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
                profile = argv[++i];
            } else if (!agent_name) {
                agent_name = argv[i];
            } else {
                usage(); return 2;
            }
        }
        if (!agent_name) { usage(); return 2; }
        return cmd_create(agent_name, profile);
    }
    if (strcmp(cmd, "profiles") == 0) {
        if (argc != 2) { usage(); return 2; }
        return cmd_profiles();
    }
    if (strcmp(cmd, "show-profile") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_show_profile(argv[2]);
    }
    if (strcmp(cmd, "set-profile") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_set_profile(argv[2], argv[3]);
    }
    if (strcmp(cmd, "config") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_config(argv[2], argv[3]);
    }
    if (strcmp(cmd, "set-goal") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_set_goal(argv[2], argv[3]);
    }
    if (strcmp(cmd, "grant") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cap_append(argv[2], "allow", argv[3]);
    }
    if (strcmp(cmd, "deny") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cap_append(argv[2], "deny", argv[3]);
    }
    if (strcmp(cmd, "set-limit") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_set_limit(argv[2], argv[3]);
    }
    if (strcmp(cmd, "start") == 0) {
        const char *aname = NULL, *rpath = NULL;
        const char *agentfs_mount = NULL;
        int fs_o = -1, sc_o = -1, cg_o = -1;
        for (int i = 2; i < argc; i++) {
            if ((strcmp(argv[i], "--exec") == 0 || strcmp(argv[i], "--runtime") == 0)
                && i + 1 < argc) {
                rpath = argv[++i];
            } else if (strcmp(argv[i], "--enforce-fs") == 0) {
                fs_o = 1;
            } else if (strcmp(argv[i], "--no-enforce-fs") == 0) {
                fs_o = 0;
            } else if (strcmp(argv[i], "--seccomp") == 0 && i + 1 < argc) {
                const char *v = argv[++i];
                if      (strcmp(v, "minimal") == 0) sc_o = 1;
                else if (strcmp(v, "off")     == 0) sc_o = 0;
                else { usage(); return 2; }
            } else if (strcmp(argv[i], "--cgroup") == 0) {
                cg_o = 1;
            } else if (strcmp(argv[i], "--no-cgroup") == 0) {
                cg_o = 0;
            } else if (strcmp(argv[i], "--agentfs") == 0 && i + 1 < argc) {
                agentfs_mount = argv[++i];
            } else if (!aname) {
                aname = argv[i];
            } else { usage(); return 2; }
        }
        if (!aname || !rpath) { usage(); return 2; }
        return cmd_start(aname, rpath, fs_o, sc_o, cg_o, agentfs_mount);
    }
    if (strcmp(cmd, "send") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_send(argv[2], argv[3]);
    }
    if (strcmp(cmd, "ping") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_ping(argv[2]);
    }
    if (strcmp(cmd, "list") == 0) {
        if (argc != 2) { usage(); return 2; }
        return cmd_list();
    }
    if (strcmp(cmd, "inspect") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_inspect(argv[2]);
    }
    if (strcmp(cmd, "logs") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_logs(argv[2]);
    }
    if (strcmp(cmd, "artifacts") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_artifacts(argv[2]);
    }
    if (strcmp(cmd, "tasks") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_tasks(argv[2]);
    }
    if (strcmp(cmd, "task") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_task(argv[2], argv[3]);
    }
    if (strcmp(cmd, "stop") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_stop(argv[2]);
    }
    if (strcmp(cmd, "kill") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_kill(argv[2]);
    }
    if (strcmp(cmd, "enable") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_enable(argv[2], 1);
    }
    if (strcmp(cmd, "disable") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_enable(argv[2], 0);
    }
    if (strcmp(cmd, "set-restart-policy") == 0) {
        if (argc != 4) { usage(); return 2; }
        return cmd_set_restart_policy(argv[2], argv[3]);
    }
    if (strcmp(cmd, "restart") == 0) {
        if (argc != 3) { usage(); return 2; }
        return cmd_restart(argv[2]);
    }
    if (strcmp(cmd, "daemon-shutdown") == 0) {
        if (argc != 2) { usage(); return 2; }
        return cmd_daemon_shutdown();
    }
    usage();
    return 2;
}
