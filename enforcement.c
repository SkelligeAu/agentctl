#include "enforcement.h"
#include "profiles.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ---------- name conversions ---------- */

const char *enforce_fs_name(enforce_fs_mode_t m)
{
    return (m == ENFORCE_FS_LANDLOCK) ? "landlock" : "off";
}
const char *seccomp_mode_name(seccomp_mode_t m)
{
    return (m == SECCOMP_MINIMAL) ? "minimal" : "off";
}
const char *enforce_status_word(int status)
{
    switch (status) {
        case ENF_STATUS_ACTIVE:      return "active";
        case ENF_STATUS_INACTIVE:    return "inactive";
        case ENF_STATUS_UNAVAILABLE: return "unavailable";
    }
    return "?";
}

/* ---------- caps walker (used by landlock builder; Linux-only) ---------- */

#if defined(__linux__)
/* Iterate `allow <verb>` entries; for each "<verb>:<param>" call cb(param). */
typedef void (*allow_cb)(const char *param, void *ud);

static void iter_allow_with_verb(const char *caps_text, const char *verb,
                                 allow_cb cb, void *ud)
{
    if (!caps_text) return;
    size_t vlen = strlen(verb);
    const char *p = caps_text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        const char *line = p;
        while (llen > 0 && (*line == ' ' || *line == '\t')) { line++; llen--; }
        if (llen > 5 && strncmp(line, "allow ", 6) == 0) {
            const char *kw = line + 6;
            size_t kwlen = llen - 6;
            while (kwlen > 0 && (*kw == ' ' || *kw == '\t')) { kw++; kwlen--; }
            if (kwlen > vlen && memcmp(kw, verb, vlen) == 0 && kw[vlen] == ':') {
                const char *v = kw + vlen + 1;
                size_t vl = kwlen - vlen - 1;
                while (vl > 0 && (v[vl-1] == ' ' || v[vl-1] == '\t' || v[vl-1] == '\r')) vl--;
                if (vl > 0 && vl < 4096) {
                    char buf[4096];
                    memcpy(buf, v, vl);
                    buf[vl] = '\0';
                    cb(buf, ud);
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
}
#endif  /* __linux__ */

/* ---------- enforcement.req / enforcement.applied ---------- */

int enforcement_write_req(const char *agent_name, const enforcement_spec_t *spec)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent_name, "enforcement.req") != 0)
        return -1;
    char buf[512];
    int w = snprintf(buf, sizeof(buf),
                     "enforce_fs=%s\nseccomp=%s\ncgroup=%s\n"
                     "cgroup_memory_max=%ld\ncgroup_pids_max=%ld\n"
                     "cgroup_cpu_max=%s\n",
                     enforce_fs_name(spec->fs_mode),
                     seccomp_mode_name(spec->sc_mode),
                     spec->cgroup_on ? "on" : "off",
                     spec->cg_memory_max, spec->cg_pids_max,
                     spec->cg_cpu_max[0] ? spec->cg_cpu_max : "-");
    if (w < 0 || (size_t)w >= sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
    return atomic_write_file(path, buf, (size_t)w, 0600);
}

static int write_state_file(const char *agent_name,
                            const enforcement_state_t *st)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent_name, "enforcement.applied") != 0)
        return -1;
    char buf[1024];
    int w = snprintf(buf, sizeof(buf),
                     "landlock_status=%s\nlandlock_rules=%d\n"
                     "seccomp_status=%s\n"
                     "cgroup_status=%s\ncgroup_path=%s\n"
                     "reason=%s\n",
                     enforce_status_word(st->landlock_status),
                     st->landlock_rules,
                     enforce_status_word(st->seccomp_status),
                     enforce_status_word(st->cgroup_status),
                     st->cgroup_path[0] ? st->cgroup_path : "-",
                     st->reason[0] ? st->reason : "-");
    if (w < 0 || (size_t)w >= sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
    return atomic_write_file(path, buf, (size_t)w, 0600);
}

void enforcement_audit_status(const char *agent_name)
{
    enforcement_state_t st;
    if (enforcement_read_state(agent_name, &st) != 0) return;
    if (st.landlock_status == ENF_STATUS_ACTIVE)
        audit_log(agent_name, "landlock active rules=%d", st.landlock_rules);
    else if (st.landlock_status == ENF_STATUS_UNAVAILABLE)
        audit_log(agent_name, "landlock unavailable: %s",
                  st.reason[0] ? st.reason : "?");
    if (st.seccomp_status == ENF_STATUS_ACTIVE)
        audit_log(agent_name, "seccomp minimal active");
    else if (st.seccomp_status == ENF_STATUS_UNAVAILABLE)
        audit_log(agent_name, "seccomp unavailable: %s",
                  st.reason[0] ? st.reason : "?");
    if (st.cgroup_status == ENF_STATUS_ACTIVE)
        audit_log(agent_name, "cgroup active path=%s", st.cgroup_path);
}

int enforcement_read_state(const char *agent_name, enforcement_state_t *out)
{
    memset(out, 0, sizeof(*out));
    out->landlock_status = ENF_STATUS_INACTIVE;
    out->seccomp_status  = ENF_STATUS_INACTIVE;
    out->cgroup_status   = ENF_STATUS_INACTIVE;

    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent_name, "enforcement.applied") != 0)
        return -1;
    char buf[1024];
    if (read_small_file(path, buf, sizeof(buf), NULL) != 0) return -1;

    char *p = buf;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            const char *k = p, *v = eq + 1;
            if      (!strcmp(k, "landlock_status")) {
                if (!strcmp(v, "active"))      out->landlock_status = ENF_STATUS_ACTIVE;
                else if (!strcmp(v, "unavailable")) out->landlock_status = ENF_STATUS_UNAVAILABLE;
            } else if (!strcmp(k, "landlock_rules")) out->landlock_rules = atoi(v);
            else if  (!strcmp(k, "seccomp_status")) {
                if (!strcmp(v, "active"))      out->seccomp_status = ENF_STATUS_ACTIVE;
                else if (!strcmp(v, "unavailable")) out->seccomp_status = ENF_STATUS_UNAVAILABLE;
            } else if (!strcmp(k, "cgroup_status")) {
                if (!strcmp(v, "active"))      out->cgroup_status = ENF_STATUS_ACTIVE;
                else if (!strcmp(v, "unavailable")) out->cgroup_status = ENF_STATUS_UNAVAILABLE;
            } else if (!strcmp(k, "cgroup_path")) {
                if (strcmp(v, "-") != 0)
                    snprintf(out->cgroup_path, sizeof(out->cgroup_path), "%s", v);
            } else if (!strcmp(k, "reason")) {
                if (strcmp(v, "-") != 0)
                    snprintf(out->reason, sizeof(out->reason), "%s", v);
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    return 0;
}

/* ============================================================
 * LINUX BACKEND
 * ============================================================ */

#if defined(__linux__)

#include <sys/syscall.h>
#include <sys/prctl.h>

/* ---- cgroup v2 ---- */

static int write_str(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    size_t l = strlen(val);
    if (write(fd, val, l) != (ssize_t)l) { int e = errno; close(fd); errno = e; return -1; }
    close(fd);
    return 0;
}

static int cgroup_setup_linux(const char *agent_name,
                              const enforcement_spec_t *spec,
                              enforcement_state_t *st)
{
    char dir[256];
    int n = snprintf(dir, sizeof(dir), "/sys/fs/cgroup/agents/%s", agent_name);
    if (n < 0 || (size_t)n >= sizeof(dir)) { errno = ENAMETOOLONG; return -1; }

    /* Make sure parent exists. We don't try to mount cgroup2 or arrange
     * delegation — that's a host setup concern. We just try to mkdir, and
     * report any error verbatim. */
    if (mkdir("/sys/fs/cgroup/agents", 0755) != 0 && errno != EEXIST) {
        snprintf(st->reason, sizeof(st->reason),
                 "mkdir /sys/fs/cgroup/agents: %s", strerror(errno));
        st->cgroup_status = ENF_STATUS_UNAVAILABLE;
        return -1;
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        snprintf(st->reason, sizeof(st->reason),
                 "cgroup mkdir: %.220s", strerror(errno));
        st->cgroup_status = ENF_STATUS_UNAVAILABLE;
        return -1;
    }
    snprintf(st->cgroup_path, sizeof(st->cgroup_path), "%s", dir);

    char path[512];
    char val[64];
    if (spec->cg_memory_max > 0) {
        snprintf(path, sizeof(path), "%s/memory.max", dir);
        snprintf(val, sizeof(val), "%ld", spec->cg_memory_max);
        if (write_str(path, val) != 0) {
            snprintf(st->reason, sizeof(st->reason),
                     "memory.max: %s", strerror(errno));
        }
    }
    if (spec->cg_pids_max > 0) {
        snprintf(path, sizeof(path), "%s/pids.max", dir);
        snprintf(val, sizeof(val), "%ld", spec->cg_pids_max);
        if (write_str(path, val) != 0) {
            snprintf(st->reason, sizeof(st->reason),
                     "pids.max: %s", strerror(errno));
        }
    }
    if (spec->cg_cpu_max[0]) {
        snprintf(path, sizeof(path), "%s/cpu.max", dir);
        /* cpu.max wants "quota period"; users write "quota/period". Convert. */
        char buf[64];
        snprintf(buf, sizeof(buf), "%s", spec->cg_cpu_max);
        char *slash = strchr(buf, '/');
        if (slash) *slash = ' ';
        if (write_str(path, buf) != 0) {
            snprintf(st->reason, sizeof(st->reason),
                     "cpu.max: %s", strerror(errno));
        }
    }
    st->cgroup_status = ENF_STATUS_ACTIVE;
    return 0;
}

static int cgroup_attach_pid_linux(const enforcement_state_t *st, pid_t pid)
{
    if (st->cgroup_status != ENF_STATUS_ACTIVE) return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/cgroup.procs", st->cgroup_path);
    char val[32];
    snprintf(val, sizeof(val), "%ld", (long)pid);
    return write_str(path, val);
}

/* ---- Landlock ---- */

#if defined(__has_include)
#  if __has_include(<linux/landlock.h>)
#    include <linux/landlock.h>
#    define HAVE_LANDLOCK 1
#  endif
#endif

#ifdef HAVE_LANDLOCK
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

static int sys_landlock_create_ruleset(const struct landlock_ruleset_attr *a,
                                        size_t sz, uint32_t flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, a, sz, flags);
}
static int sys_landlock_add_rule(int rsfd, enum landlock_rule_type t,
                                 const void *attr, uint32_t flags)
{
    return (int)syscall(__NR_landlock_add_rule, rsfd, t, attr, flags);
}
static int sys_landlock_restrict_self(int rsfd, uint32_t flags)
{
    return (int)syscall(__NR_landlock_restrict_self, rsfd, flags);
}

struct ll_ctx { int rsfd; int rules; uint64_t read_mask; uint64_t write_mask; };

static int add_path_rule(struct ll_ctx *c, const char *path, uint64_t access)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd == -1) return -1;
    struct landlock_path_beneath_attr a = {0};
    a.allowed_access = access;
    a.parent_fd = fd;
    int rc = sys_landlock_add_rule(c->rsfd, LANDLOCK_RULE_PATH_BENEATH, &a, 0);
    close(fd);
    if (rc == 0) c->rules++;
    return rc;
}

static void add_read_cb_(const char *p, void *ud)
{
    struct ll_ctx *c = ud;
    (void)add_path_rule(c, p, c->read_mask);
}
static void add_write_cb_(const char *p, void *ud)
{
    struct ll_ctx *c = ud;
    (void)add_path_rule(c, p, c->read_mask | c->write_mask);
}

static int landlock_apply_linux(const char *agent_name,
                                const char *runtime_path,
                                const char *caps_text,
                                enforcement_state_t *st)
{
    /* Detect ABI version. */
    int abi = sys_landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        st->landlock_status = ENF_STATUS_UNAVAILABLE;
        snprintf(st->reason, sizeof(st->reason),
                 "landlock unsupported: %s", strerror(errno));
        return -1;
    }

    uint64_t read_mask  = LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t execute_mask = LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t write_mask = LANDLOCK_ACCESS_FS_WRITE_FILE |
                          LANDLOCK_ACCESS_FS_REMOVE_FILE |
                          LANDLOCK_ACCESS_FS_REMOVE_DIR |
                          LANDLOCK_ACCESS_FS_MAKE_REG |
                          LANDLOCK_ACCESS_FS_MAKE_DIR |
                          LANDLOCK_ACCESS_FS_MAKE_SOCK |
                          LANDLOCK_ACCESS_FS_MAKE_FIFO |
                          LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                          LANDLOCK_ACCESS_FS_MAKE_CHAR |
                          LANDLOCK_ACCESS_FS_MAKE_SYM |
                          (abi >= 2 ? LANDLOCK_ACCESS_FS_REFER : 0);

    struct landlock_ruleset_attr attr = {0};
    attr.handled_access_fs = read_mask | write_mask | execute_mask;

    int rsfd = sys_landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (rsfd < 0) {
        st->landlock_status = ENF_STATUS_UNAVAILABLE;
        snprintf(st->reason, sizeof(st->reason),
                 "landlock create_ruleset: %s", strerror(errno));
        return -1;
    }

    struct ll_ctx c = { rsfd, 0, read_mask, write_mask };

    /* Default baseline reads: things any process needs to function. */
    static const char *default_reads[] = {
        "/etc", "/proc", "/dev/null", "/dev/urandom",
        NULL
    };
    for (int i = 0; default_reads[i]; i++) add_path_rule(&c, default_reads[i], read_mask);
    static const char *default_runtime_dirs[] = {
        "/usr", "/lib", "/lib64", NULL
    };
    for (int i = 0; default_runtime_dirs[i]; i++)
        add_path_rule(&c, default_runtime_dirs[i], read_mask | execute_mask);
    /* LANDLOCK_RULE_PATH_BENEATH execute grants are directory-anchored. Keep
     * the implicit runtime grant to the executable's immediate directory. */
    if (runtime_path && *runtime_path) {
        char runtime_dir[MAX_PATHBUF];
        snprintf(runtime_dir, sizeof(runtime_dir), "%s", runtime_path);
        char *slash = strrchr(runtime_dir, '/');
        if (slash) {
            if (slash == runtime_dir) slash[1] = '\0';
            else *slash = '\0';
            add_path_rule(&c, runtime_dir, read_mask | execute_mask);
        }
    }
    /* Per-agent boundary: operator configuration is readable but never
     * writable by the child. Application state lives under data/. Runtime
     * status remains writable for the v1 status/audit API, but contains no
     * policy or lifecycle inputs. Do not grant the shared agents/ tree. */
    char config_dir[MAX_PATHBUF], runtime_dir[MAX_PATHBUF], data_dir[MAX_PATHBUF];
    if (agent_config_dir(config_dir, sizeof(config_dir), agent_name) == 0)
        add_path_rule(&c, config_dir, read_mask);
    if (agent_runtime_dir(runtime_dir, sizeof(runtime_dir), agent_name) == 0)
        add_path_rule(&c, runtime_dir, read_mask | write_mask);
    if (agent_data_dir(data_dir, sizeof(data_dir), agent_name) == 0)
        add_path_rule(&c, data_dir, read_mask | write_mask);

    /* Caps-driven extras. */
    iter_allow_with_verb(caps_text, "fs.read",  add_read_cb_,  &c);
    iter_allow_with_verb(caps_text, "fs.write", add_write_cb_, &c);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        snprintf(st->reason, sizeof(st->reason),
                 "PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
        close(rsfd);
        st->landlock_status = ENF_STATUS_UNAVAILABLE;
        return -1;
    }
    if (sys_landlock_restrict_self(rsfd, 0) != 0) {
        snprintf(st->reason, sizeof(st->reason),
                 "landlock restrict_self: %s", strerror(errno));
        close(rsfd);
        st->landlock_status = ENF_STATUS_UNAVAILABLE;
        return -1;
    }
    close(rsfd);
    st->landlock_status = ENF_STATUS_ACTIVE;
    st->landlock_rules  = c.rules;
    return 0;
}

#else  /* !HAVE_LANDLOCK */
static int landlock_apply_linux(const char *agent_name,
                                const char *runtime_path,
                                const char *caps_text,
                                enforcement_state_t *st)
{
    (void)agent_name; (void)runtime_path; (void)caps_text;
    st->landlock_status = ENF_STATUS_UNAVAILABLE;
    snprintf(st->reason, sizeof(st->reason),
             "kernel headers lack <linux/landlock.h>");
    return -1;
}
#endif

/* ---- seccomp (minimal allow-list) ---- */

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#  define SC_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define SC_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#  define SC_AUDIT_ARCH 0
#endif

#define SC_ALLOW(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int seccomp_apply_linux(enforcement_state_t *st)
{
    if (SC_AUDIT_ARCH == 0) {
        st->seccomp_status = ENF_STATUS_UNAVAILABLE;
        snprintf(st->reason, sizeof(st->reason), "seccomp arch not supported");
        return -1;
    }

    struct sock_filter filter[] = {
        /* Arch check. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Load syscall number. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),

        /* Core IO. */
        SC_ALLOW(__NR_read), SC_ALLOW(__NR_write),
        SC_ALLOW(__NR_readv), SC_ALLOW(__NR_writev),
        SC_ALLOW(__NR_close), SC_ALLOW(__NR_lseek),
        SC_ALLOW(__NR_dup), SC_ALLOW(__NR_dup3),
        SC_ALLOW(__NR_fcntl),
#ifdef __NR_open
        SC_ALLOW(__NR_open),
#endif
        SC_ALLOW(__NR_openat),
#ifdef __NR_stat
        SC_ALLOW(__NR_stat), SC_ALLOW(__NR_lstat), SC_ALLOW(__NR_fstat),
#endif
        SC_ALLOW(__NR_newfstatat), SC_ALLOW(__NR_fstatfs),
        SC_ALLOW(__NR_unlinkat),
        SC_ALLOW(__NR_renameat), SC_ALLOW(__NR_renameat2),
        SC_ALLOW(__NR_fchmod), SC_ALLOW(__NR_fchmodat),
        SC_ALLOW(__NR_truncate), SC_ALLOW(__NR_ftruncate),
        SC_ALLOW(__NR_getdents64),
        SC_ALLOW(__NR_readlinkat),
        SC_ALLOW(__NR_faccessat), SC_ALLOW(__NR_faccessat2),
        SC_ALLOW(__NR_pipe2),
        /* x86_64-only legacy syscalls (replaced by *at variants on arm64). */
#ifdef __NR_mkdir
        SC_ALLOW(__NR_mkdir),
#endif
#ifdef __NR_unlink
        SC_ALLOW(__NR_unlink),
#endif
#ifdef __NR_rename
        SC_ALLOW(__NR_rename),
#endif
#ifdef __NR_chmod
        SC_ALLOW(__NR_chmod),
#endif
#ifdef __NR_readlink
        SC_ALLOW(__NR_readlink),
#endif
#ifdef __NR_access
        SC_ALLOW(__NR_access),
#endif
#ifdef __NR_readdir
        SC_ALLOW(__NR_readdir),
#endif
        SC_ALLOW(__NR_ioctl),

        /* Memory. */
        SC_ALLOW(__NR_mmap), SC_ALLOW(__NR_munmap), SC_ALLOW(__NR_mprotect),
        SC_ALLOW(__NR_brk), SC_ALLOW(__NR_madvise),

        /* Process/identity. */
        SC_ALLOW(__NR_getpid), SC_ALLOW(__NR_getppid), SC_ALLOW(__NR_gettid),
        SC_ALLOW(__NR_getuid), SC_ALLOW(__NR_geteuid),
        SC_ALLOW(__NR_getgid), SC_ALLOW(__NR_getegid),
        SC_ALLOW(__NR_exit), SC_ALLOW(__NR_exit_group),

        /* Signals. */
        SC_ALLOW(__NR_rt_sigaction), SC_ALLOW(__NR_rt_sigprocmask),
        SC_ALLOW(__NR_rt_sigreturn),
#ifdef __NR_sigaltstack
        SC_ALLOW(__NR_sigaltstack),
#endif

        /* Time. */
        SC_ALLOW(__NR_nanosleep), SC_ALLOW(__NR_clock_gettime),
        SC_ALLOW(__NR_clock_nanosleep),
#ifdef __NR_gettimeofday
        SC_ALLOW(__NR_gettimeofday),
#endif

        /* Poll / select. */
#ifdef __NR_poll
        SC_ALLOW(__NR_poll),
#endif
        SC_ALLOW(__NR_ppoll),
#ifdef __NR_select
        SC_ALLOW(__NR_select),
#endif
        SC_ALLOW(__NR_pselect6),

        /* Sockets (UDS). */
        SC_ALLOW(__NR_socket), SC_ALLOW(__NR_socketpair),
        SC_ALLOW(__NR_bind), SC_ALLOW(__NR_listen),
        SC_ALLOW(__NR_accept), SC_ALLOW(__NR_accept4),
        SC_ALLOW(__NR_connect), SC_ALLOW(__NR_shutdown),
        SC_ALLOW(__NR_setsockopt), SC_ALLOW(__NR_getsockopt),
        SC_ALLOW(__NR_getsockname), SC_ALLOW(__NR_getpeername),
        SC_ALLOW(__NR_sendto), SC_ALLOW(__NR_recvfrom),
        SC_ALLOW(__NR_sendmsg), SC_ALLOW(__NR_recvmsg),

        /* Threading primitives libc uses. */
        SC_ALLOW(__NR_futex), SC_ALLOW(__NR_set_robust_list),
        SC_ALLOW(__NR_get_robust_list),
#ifdef __NR_arch_prctl
        SC_ALLOW(__NR_arch_prctl),
#endif

        /* Random. */
        SC_ALLOW(__NR_getrandom),

        /* Default: return EPERM so the caller observes a clean errno and
         * can audit. KILL would be louder but harder to debug. */
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        snprintf(st->reason, sizeof(st->reason),
                 "PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
        st->seccomp_status = ENF_STATUS_UNAVAILABLE;
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        snprintf(st->reason, sizeof(st->reason),
                 "PR_SET_SECCOMP: %s", strerror(errno));
        st->seccomp_status = ENF_STATUS_UNAVAILABLE;
        return -1;
    }
    st->seccomp_status = ENF_STATUS_ACTIVE;
    return 0;
}

/* ---- public Linux entry points ---- */

int enforcement_parent_setup(const char *agent_name,
                              const enforcement_spec_t *spec,
                              enforcement_state_t *state)
{
    memset(state, 0, sizeof(*state));
    state->landlock_status = spec->fs_mode == ENFORCE_FS_LANDLOCK
                                ? ENF_STATUS_INACTIVE : ENF_STATUS_INACTIVE;
    state->seccomp_status  = ENF_STATUS_INACTIVE;
    state->cgroup_status   = ENF_STATUS_INACTIVE;

    if (spec->cgroup_on) {
        (void)cgroup_setup_linux(agent_name, spec, state);
    }
    return write_state_file(agent_name, state);
}

int enforcement_parent_attach_pid(const enforcement_state_t *state, pid_t pid)
{
    return cgroup_attach_pid_linux(state, pid);
}

int enforcement_child_apply(const char *agent_name,
                             const char *runtime_path,
                             const enforcement_spec_t *spec,
                             enforcement_state_t *state)
{
    /* state may already carry cgroup info from the parent. */
    char caps_buf[8192];
    char caps_path[MAX_PATHBUF];
    caps_buf[0] = '\0';
    if (agent_path(caps_path, sizeof(caps_path), agent_name, "policy") == 0)
        (void)read_small_file(caps_path, caps_buf, sizeof(caps_buf), NULL);

    if (spec->fs_mode == ENFORCE_FS_LANDLOCK) {
        (void)landlock_apply_linux(
            agent_name, runtime_path, caps_buf, state
        );
    }
    /* Persist after landlock so the supervisor / inspect see the rule count. */
    (void)write_state_file(agent_name, state);

    if (spec->sc_mode == SECCOMP_MINIMAL) {
        (void)seccomp_apply_linux(state);
    }
    (void)write_state_file(agent_name, state);
    return 0;
}

#else  /* not Linux */

int enforcement_parent_setup(const char *agent_name,
                              const enforcement_spec_t *spec,
                              enforcement_state_t *state)
{
    memset(state, 0, sizeof(*state));
    state->landlock_status =
        spec->fs_mode == ENFORCE_FS_LANDLOCK ? ENF_STATUS_UNAVAILABLE
                                              : ENF_STATUS_INACTIVE;
    state->seccomp_status =
        spec->sc_mode == SECCOMP_MINIMAL ? ENF_STATUS_UNAVAILABLE
                                          : ENF_STATUS_INACTIVE;
    state->cgroup_status =
        spec->cgroup_on ? ENF_STATUS_UNAVAILABLE : ENF_STATUS_INACTIVE;
    if (spec->fs_mode == ENFORCE_FS_LANDLOCK ||
        spec->sc_mode == SECCOMP_MINIMAL || spec->cgroup_on)
        snprintf(state->reason, sizeof(state->reason),
                 "unsupported on this platform");
    return write_state_file(agent_name, state);
}

int enforcement_parent_attach_pid(const enforcement_state_t *state, pid_t pid)
{
    (void)state; (void)pid;
    return 0;
}

int enforcement_child_apply(const char *agent_name,
                             const char *runtime_path,
                             const enforcement_spec_t *spec,
                             enforcement_state_t *state)
{
    (void)runtime_path; (void)spec;
    /* Same as parent_setup on non-Linux: nothing to do, just persist. */
    return write_state_file(agent_name, state);
}

#endif  /* __linux__ */
