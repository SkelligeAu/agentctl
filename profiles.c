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

static const char *PROFILE_DIRS_DEFAULT[] = {
    "/usr/lib/agents/profiles",
    "/usr/local/lib/agents/profiles",
    "./profiles",
    NULL
};

/* ---------- enum/string conversions ---------- */

const char *dispatch_name(dispatch_mode_t m)
{
    switch (m) {
        case DISPATCH_SINGLE_SHOT: return "single-shot";
        case DISPATCH_PERSISTENT:  return "persistent";
        case DISPATCH_DELEGATING:  return "delegating";
    }
    return "?";
}

const char *artifact_policy_name(artifact_policy_t p)
{
    switch (p) {
        case ARTIFACT_OVERWRITE:   return "overwrite";
        case ARTIFACT_VERSIONED:   return "versioned";
        case ARTIFACT_APPEND_ONLY: return "append-only";
    }
    return "?";
}

/* ---------- KEY=VALUE parsing ---------- */

static dispatch_mode_t parse_dispatch(const char *v)
{
    if (strcmp(v, "single-shot") == 0) return DISPATCH_SINGLE_SHOT;
    if (strcmp(v, "persistent")  == 0) return DISPATCH_PERSISTENT;
    if (strcmp(v, "delegating")  == 0) return DISPATCH_DELEGATING;
    return DISPATCH_PERSISTENT;
}
static artifact_policy_t parse_artifact_policy(const char *v)
{
    if (strcmp(v, "overwrite")   == 0) return ARTIFACT_OVERWRITE;
    if (strcmp(v, "versioned")   == 0) return ARTIFACT_VERSIONED;
    if (strcmp(v, "append-only") == 0) return ARTIFACT_APPEND_ONLY;
    return ARTIFACT_OVERWRITE;
}

static void apply_kv(profile_cfg_t *cfg, const char *k, const char *v)
{
    if      (strcmp(k, "dispatch")        == 0) cfg->dispatch        = parse_dispatch(v);
    else if (strcmp(k, "artifact_policy") == 0) cfg->artifact_policy = parse_artifact_policy(v);
    else if (strcmp(k, "idle_timeout")    == 0) {
        long t = strtol(v, NULL, 10);
        if (t < 0) t = 0;
        if (t > 86400) t = 86400;
        cfg->idle_timeout_sec = (int)t;
    }
    else if (strcmp(k, "enforce_fs") == 0) {
        cfg->enforce_fs = (strcmp(v, "landlock") == 0) ? 1 : 0;
    }
    else if (strcmp(k, "seccomp") == 0) {
        cfg->seccomp = (strcmp(v, "minimal") == 0) ? 1 : 0;
    }
    else if (strcmp(k, "cgroup") == 0) {
        cfg->cgroup = (strcmp(v, "on") == 0) ? 1 : 0;
    }
    else if (strcmp(k, "CGROUP_MEMORY_MAX") == 0) {
        long n = strtol(v, NULL, 10);
        if (n > 0) cfg->cgroup_memory_max = n;
    }
    else if (strcmp(k, "CGROUP_PIDS_MAX") == 0) {
        long n = strtol(v, NULL, 10);
        if (n > 0) cfg->cgroup_pids_max = n;
    }
    else if (strcmp(k, "CGROUP_CPU_MAX") == 0) {
        snprintf(cfg->cgroup_cpu_max, sizeof(cfg->cgroup_cpu_max), "%s", v);
    }
    /* message_policy, snapshot_policy: silently consumed (labels for now). */
}

static void parse_lines(profile_cfg_t *cfg, const char *buf)
{
    const char *p = buf;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        const char *line = p;
        while (llen > 0 && (*line == ' ' || *line == '\t')) { line++; llen--; }
        if (llen > 0 && *line != '#') {
            char tmp[256];
            if (llen < sizeof(tmp)) {
                memcpy(tmp, line, llen);
                tmp[llen] = '\0';
                char *eq = strchr(tmp, '=');
                if (eq) {
                    *eq = '\0';
                    char *k = tmp;
                    char *v = eq + 1;
                    /* trim trailing ws on key */
                    char *ke = eq;
                    while (ke > k && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = '\0';
                    /* trim trailing ws on value */
                    size_t vlen = strlen(v);
                    while (vlen > 0 && (v[vlen-1] == ' ' || v[vlen-1] == '\t' || v[vlen-1] == '\r')) {
                        v[--vlen] = '\0';
                    }
                    apply_kv(cfg, k, v);
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
}

/* ---------- builtin fallback ---------- */

static void set_builtin_defaults(profile_cfg_t *cfg)
{
    snprintf(cfg->profile_name, sizeof(cfg->profile_name), "worker");
    cfg->dispatch         = DISPATCH_PERSISTENT;
    cfg->artifact_policy  = ARTIFACT_OVERWRITE;
    cfg->idle_timeout_sec = 0;
    cfg->raw[0] = '\0';
}

/* ---------- search + load ---------- */

static void collect_search_paths(const char **out, int max)
{
    int idx = 0;
    const char *env = getenv("AGENT_PROFILES_DIR");
    if (env && *env && idx < max - 1) out[idx++] = env;
    for (int i = 0; PROFILE_DIRS_DEFAULT[i] && idx < max - 1; i++) {
        out[idx++] = PROFILE_DIRS_DEFAULT[i];
    }
    out[idx] = NULL;
}

int profile_locate(const char *profile_name, char *path_buf, size_t n)
{
    if (!profile_name || !*profile_name) { errno = EINVAL; return -1; }
    const char *dirs[8];
    collect_search_paths(dirs, 8);
    for (int i = 0; dirs[i]; i++) {
        int len = snprintf(path_buf, n, "%s/%s.profile", dirs[i], profile_name);
        if (len < 0 || (size_t)len >= n) continue;
        if (access(path_buf, R_OK) == 0) return 0;
    }
    errno = ENOENT;
    return -1;
}

int profile_read_raw(const char *profile_name, char *out, size_t n)
{
    char path[MAX_PATHBUF];
    if (profile_locate(profile_name, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    ssize_t r = read(fd, out, n - 1);
    int saved = errno;
    close(fd);
    if (r == -1) { errno = saved; return -1; }
    out[r] = '\0';
    return 0;
}

int profile_load_by_name(const char *profile_name, profile_cfg_t *out)
{
    set_builtin_defaults(out);
    snprintf(out->profile_name, sizeof(out->profile_name), "%s", profile_name);

    if (profile_read_raw(profile_name, out->raw, sizeof(out->raw)) != 0) {
        /* No file. Builtin defaults are the "worker" answer. */
        if (strcmp(profile_name, "worker") == 0) return 0;
        return -1;
    }
    parse_lines(out, out->raw);
    return 0;
}

int profile_load_for_agent(const char *agent_name, profile_cfg_t *out)
{
    char profile_name[MAX_PROFILE_NAME] = "worker";
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent_name, "profile") == 0) {
        char buf[128];
        if (read_small_file(path, buf, sizeof(buf), NULL) == 0) {
            size_t i = 0;
            while (i < sizeof(profile_name) - 1 && buf[i] &&
                   buf[i] != '\n' && buf[i] != ' ' && buf[i] != '\t') {
                profile_name[i] = buf[i]; i++;
            }
            profile_name[i] = '\0';
            if (profile_name[0] == '\0')
                snprintf(profile_name, sizeof(profile_name), "worker");
        }
    }

    if (profile_load_by_name(profile_name, out) != 0) {
        /* Unknown named profile → keep its name, use worker defaults. */
        set_builtin_defaults(out);
        snprintf(out->profile_name, sizeof(out->profile_name), "%s", profile_name);
    }

    /* Overlay per-agent config. */
    if (agent_path(path, sizeof(path), agent_name, "config") == 0) {
        char buf[MAX_PROFILE_RAW];
        if (read_small_file(path, buf, sizeof(buf), NULL) == 0) {
            parse_lines(out, buf);
        }
    }
    return 0;
}

void profile_list(profile_list_cb cb, void *ud)
{
    const char *dirs[8];
    collect_search_paths(dirs, 8);

    char seen[16][MAX_PROFILE_NAME];
    int nseen = 0;
    static const char SUFFIX[] = ".profile";
    static const size_t sl = sizeof(SUFFIX) - 1;

    for (int i = 0; dirs[i]; i++) {
        DIR *d = opendir(dirs[i]);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            size_t l = strlen(e->d_name);
            if (l <= sl) continue;
            if (memcmp(e->d_name + l - sl, SUFFIX, sl) != 0) continue;
            size_t nl = l - sl;
            if (nl >= sizeof(seen[0])) continue;
            char name[MAX_PROFILE_NAME];
            memcpy(name, e->d_name, nl);
            name[nl] = '\0';

            int dup = 0;
            for (int j = 0; j < nseen; j++) {
                if (strcmp(seen[j], name) == 0) { dup = 1; break; }
            }
            if (dup) continue;
            if (nseen < 16) {
                snprintf(seen[nseen], sizeof(seen[nseen]), "%s", name);
                nseen++;
            }
            cb(name, ud);
        }
        closedir(d);
    }
}

/* ---------- artifact policy ---------- */

static int valid_artifact_name(const char *name)
{
    if (!name) return 0;
    size_t len = strlen(name);
    if (len == 0 || len > 127 || name[0] == '.') return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}

static void timestamp_utc(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    if (strftime(out, n, "%Y%m%dT%H%M%SZ", &tm) == 0 && n > 0) out[0] = '\0';
}

static int split_stem_ext(const char *base, char *stem, size_t sn,
                          char *ext, size_t en)
{
    const char *dot = strrchr(base, '.');
    if (dot && dot != base) {
        size_t sl = (size_t)(dot - base);
        if (sl >= sn || strlen(dot) >= en) return -1;
        memcpy(stem, base, sl);
        stem[sl] = '\0';
        snprintf(ext, en, "%s", dot);
        return 0;
    }
    if (strlen(base) >= sn) return -1;
    snprintf(stem, sn, "%s", base);
    ext[0] = '\0';
    return 0;
}

int write_artifact(const char *agent_name, const char *base_filename,
                   const void *buf, size_t n, artifact_policy_t policy)
{
    if (!valid_artifact_name(base_filename)) { errno = EINVAL; return -1; }
    char path[MAX_PATHBUF];
    char rel[256];

    if (policy == ARTIFACT_OVERWRITE) {
        int w = snprintf(rel, sizeof(rel), "artifacts/%s", base_filename);
        if (w < 0 || (size_t)w >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
        if (agent_path(path, sizeof(path), agent_name, rel) != 0) return -1;
        return atomic_write_file(path, buf, n, 0600);
    }
    if (policy == ARTIFACT_VERSIONED) {
        char stem[128], ext[32], ts[24];
        if (split_stem_ext(base_filename, stem, sizeof(stem), ext, sizeof(ext)) != 0) {
            errno = ENAMETOOLONG; return -1;
        }
        timestamp_utc(ts, sizeof(ts));
        int w = snprintf(rel, sizeof(rel), "artifacts/%s-%s%s", stem, ts, ext);
        if (w < 0 || (size_t)w >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
        if (agent_path(path, sizeof(path), agent_name, rel) != 0) return -1;
        return atomic_write_file(path, buf, n, 0600);
    }
    /* APPEND_ONLY */
    int w = snprintf(rel, sizeof(rel), "artifacts/%s", base_filename);
    if (w < 0 || (size_t)w >= sizeof(rel)) { errno = ENAMETOOLONG; return -1; }
    if (agent_path(path, sizeof(path), agent_name, rel) != 0) return -1;

    char banner[80];
    char ts[24];
    timestamp_utc(ts, sizeof(ts));
    int bl = snprintf(banner, sizeof(banner), "\n----- %s -----\n", ts);
    if (bl < 0) return -1;
    if (append_file(path, banner, (size_t)bl, 0600) != 0) return -1;
    if (append_file(path, buf, n, 0600) != 0) return -1;
    return 0;
}

/* ---------- KEY=VALUE upsert ---------- */

int kv_file_set(const char *path, const char *kv)
{
    const char *eq = strchr(kv, '=');
    if (!eq || eq == kv) { errno = EINVAL; return -1; }
    size_t keylen = (size_t)(eq - kv);

    char old[4096];
    size_t olen = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        ssize_t r = read(fd, old, sizeof(old) - 1);
        close(fd);
        if (r > 0) olen = (size_t)r;
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
            if (w < 0 || (size_t)w >= sizeof(neu) - off) { errno = ENAMETOOLONG; return -1; }
            off += (size_t)w;
            replaced = 1;
        } else if (llen > 0) {
            if (off + llen + 1 >= sizeof(neu)) { errno = ENAMETOOLONG; return -1; }
            memcpy(neu + off, p, llen);
            off += llen;
            neu[off++] = '\n';
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (!replaced) {
        int w = snprintf(neu + off, sizeof(neu) - off, "%s\n", kv);
        if (w < 0 || (size_t)w >= sizeof(neu) - off) { errno = ENAMETOOLONG; return -1; }
        off += (size_t)w;
    }
    return atomic_write_file(path, neu, off, 0600);
}
