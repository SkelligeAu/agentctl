/* psa(1) — "ps for agents."
 *
 * Walks <root>/agents/<name>/, joins each agent dir with live process info
 * read from /proc (Linux) or libproc (macOS), and prints one row per agent.
 *
 * Bounded buffers, no malloc, no ncurses, no color. */

#include "common.h"
#include "enforcement.h"
#include "profiles.h"
#include "tasks.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <libproc.h>
#  include <sys/proc_info.h>
#endif

#define GOAL_DISPLAY     40
#define STATE_DISPLAY    8
#define NAME_DISPLAY     18
#define PROFILE_DISPLAY  10
#define PLANNER_DISPLAY  12

struct agent_row {
    char   name[MAX_NAME];
    pid_t  pid;            /* 0 if no pid file */
    int    alive;
    char   state[16];      /* "running", "sleep", "dead", ... */
    double cpu_pct;        /* -1 if unknown */
    long   mem_kb;         /* -1 if unknown */
    char   profile[MAX_NAME];
    char   planner[16];
    int    tasks_total;
    int    tasks_active;
    char   fs[4];
    char   sc[4];
    char   cg[4];
    char   sup[8];       /* "agentd" | "direct" | "-" */
    char   ipc[8];       /* "uds" | "agentfs" */
    int    restart_count;
    char   goal[GOAL_DISPLAY + 4];
};

/* ---------- per-platform process inspection ---------- */

#if defined(__linux__)
static int read_uptime_seconds(double *out)
{
    int fd = open("/proc/uptime", O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    *out = strtod(buf, NULL);
    return 0;
}

static void map_state_char(char c, char *out, size_t n)
{
    switch (c) {
        case 'R': snprintf(out, n, "running"); break;
        case 'S': snprintf(out, n, "sleep");   break;
        case 'D': snprintf(out, n, "iowait");  break;
        case 'T': snprintf(out, n, "stopped"); break;
        case 't': snprintf(out, n, "traced");  break;
        case 'Z': snprintf(out, n, "zombie");  break;
        case 'X': snprintf(out, n, "dead");    break;
        case 'I': snprintf(out, n, "idle");    break;
        default:  snprintf(out, n, "?%c", c);  break;
    }
}

static int fill_proc_info(pid_t pid, struct agent_row *r)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* comm field in /proc/<pid>/stat is (name) and may contain spaces or ')'.
     * Strategy: find the LAST ')' — everything after it is unambiguous. */
    char *rparen = strrchr(buf, ')');
    if (!rparen) return -1;

    /* Fields after ')': state ppid pgrp session tty_nr tpgid flags
     *   minflt cminflt majflt cmajflt utime stime cutime cstime
     *   priority nice num_threads itrealvalue starttime vsize rss ...
     * 1-indexed against the original line; field 3 is state, 14 utime,
     * 15 stime, 22 starttime, 24 rss. */
    char state_c = '?';
    long long utime = 0, stime = 0, starttime = 0, rss_pages = 0;
    int got = sscanf(rparen + 2,
        "%c "                                 /* state */
        "%*d %*d %*d %*d %*d "                /* ppid pgrp session tty tpgid */
        "%*u %*u %*u %*u %*u "                /* flags minflt cminflt majflt cmajflt */
        "%lld %lld "                          /* utime stime */
        "%*d %*d %*d %*d %*d %*d "            /* cutime cstime prio nice nthr itreal */
        "%lld "                               /* starttime */
        "%*u %lld",                           /* vsize rss */
        &state_c, &utime, &stime, &starttime, &rss_pages);
    if (got < 5) return -1;

    map_state_char(state_c, r->state, sizeof(r->state));

    long ticks  = sysconf(_SC_CLK_TCK);
    long pagesz = sysconf(_SC_PAGESIZE);
    if (ticks <= 0)  ticks  = 100;
    if (pagesz <= 0) pagesz = 4096;

    double uptime = 0.0;
    if (read_uptime_seconds(&uptime) == 0) {
        double age = uptime - (double)starttime / (double)ticks;
        if (age < 0.01) age = 0.01;
        double cpu_sec = (double)(utime + stime) / (double)ticks;
        r->cpu_pct = (cpu_sec / age) * 100.0;
    }
    r->mem_kb = rss_pages * pagesz / 1024;
    return 0;
}

#elif defined(__APPLE__)
static void map_apple_state(uint32_t s, char *out, size_t n)
{
    /* Values from <sys/proc_info.h>: SIDL=1 SRUN=2 SSLEEP=3 SSTOP=4 SZOMB=5 */
    switch (s) {
        case 1: snprintf(out, n, "idle");    break;
        case 2: snprintf(out, n, "running"); break;
        case 3: snprintf(out, n, "sleep");   break;
        case 4: snprintf(out, n, "stopped"); break;
        case 5: snprintf(out, n, "zombie");  break;
        default: snprintf(out, n, "?%u", s); break;
    }
}

static int fill_proc_info(pid_t pid, struct agent_row *r)
{
    struct proc_taskinfo ti;
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti)) != (int)sizeof(ti))
        return -1;

    struct proc_bsdinfo bi;
    int got_bsd =
        (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi)) == (int)sizeof(bi));

    if (got_bsd) map_apple_state(bi.pbi_status, r->state, sizeof(r->state));
    else         snprintf(r->state, sizeof(r->state), "?");

    r->mem_kb = (long)(ti.pti_resident_size / 1024);

    if (got_bsd) {
        struct timeval now;
        gettimeofday(&now, NULL);
        double now_sec = (double)now.tv_sec + (double)now.tv_usec / 1e6;
        double start_sec = (double)bi.pbi_start_tvsec +
                           (double)bi.pbi_start_tvusec / 1e6;
        double age = now_sec - start_sec;
        if (age < 0.01) age = 0.01;
        double cpu_sec = (double)(ti.pti_total_user + ti.pti_total_system) / 1e9;
        r->cpu_pct = (cpu_sec / age) * 100.0;
    }
    return 0;
}
#else
static int fill_proc_info(pid_t pid, struct agent_row *r)
{
    (void)pid;
    snprintf(r->state, sizeof(r->state), "?");
    return -1;
}
#endif

/* ---------- per-agent row ---------- */

static void read_goal_first_line(const char *name, char *out, size_t n)
{
    char p[MAX_PATHBUF];
    if (agent_path(p, sizeof(p), name, "goal") != 0) { out[0] = '\0'; return; }
    char buf[512];
    size_t len = 0;
    if (read_small_file(p, buf, sizeof(buf), &len) != 0) { out[0] = '\0'; return; }
    size_t i = 0;
    while (i < len && buf[i] != '\n' && i + 1 < n) { out[i] = buf[i]; i++; }
    out[i] = '\0';
}

static int collect_row(const char *name, struct agent_row *r)
{
    memset(r, 0, sizeof(*r));
    size_t nl = strlen(name);
    if (nl >= sizeof(r->name)) nl = sizeof(r->name) - 1;
    memcpy(r->name, name, nl);
    r->name[nl] = '\0';

    r->cpu_pct = -1.0;
    r->mem_kb  = -1;
    snprintf(r->state, sizeof(r->state), "-");

    /* status file gives a snapshot for non-running agents */
    char buf[64];
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "status") == 0 &&
        read_small_file(path, buf, sizeof(buf), NULL) == 0) {
        size_t i = 0;
        while (i < sizeof(r->state) - 1 && buf[i] && buf[i] != '\n') {
            r->state[i] = buf[i]; i++;
        }
        r->state[i] = '\0';
    }

    if (read_pid_file(name, &r->pid) == 0) {
        r->alive = run_alive(r->pid);
        if (r->alive) {
            if (fill_proc_info(r->pid, r) != 0) {
                snprintf(r->state, sizeof(r->state), "gone");
                r->alive = 0;
            }
        } else {
            snprintf(r->state, sizeof(r->state), "dead");
        }
    } else {
        r->pid = 0;
    }

    read_goal_first_line(name, r->goal, sizeof(r->goal));

    {
        profile_cfg_t cfg;
        if (profile_load_for_agent(name, &cfg) == 0) {
            snprintf(r->profile, sizeof(r->profile), "%s", cfg.profile_name);
            snprintf(r->planner, sizeof(r->planner), "%s", dispatch_name(cfg.dispatch));
        } else {
            snprintf(r->profile, sizeof(r->profile), "-");
            snprintf(r->planner, sizeof(r->planner), "-");
        }
    }

    r->tasks_total  = task_count_total(name);
    r->tasks_active = task_count_active(name);

    {
        enforcement_state_t es;
        if (enforcement_read_state(name, &es) == 0) {
            snprintf(r->fs, sizeof(r->fs),
                     es.landlock_status == ENF_STATUS_ACTIVE      ? "LL"  :
                     es.landlock_status == ENF_STATUS_UNAVAILABLE ? "??"  : "-");
            snprintf(r->sc, sizeof(r->sc),
                     es.seccomp_status  == ENF_STATUS_ACTIVE      ? "min" :
                     es.seccomp_status  == ENF_STATUS_UNAVAILABLE ? "??"  : "-");
            snprintf(r->cg, sizeof(r->cg),
                     es.cgroup_status   == ENF_STATUS_ACTIVE      ? "yes" :
                     es.cgroup_status   == ENF_STATUS_UNAVAILABLE ? "??"  : "-");
        } else {
            snprintf(r->fs, sizeof(r->fs), "-");
            snprintf(r->sc, sizeof(r->sc), "-");
            snprintf(r->cg, sizeof(r->cg), "-");
        }
    }

    {
        char buf[32];
        if (read_agent_setting(name, "supervisor", buf, sizeof(buf)) == 0)
            snprintf(r->sup, sizeof(r->sup), "%.7s", buf);
        else
            snprintf(r->sup, sizeof(r->sup), "-");
        r->restart_count = 0;
        if (read_agent_setting(name, "restart_count", buf, sizeof(buf)) == 0)
            r->restart_count = atoi(buf);
    }
    {
        transport_cfg_t tcfg;
        if (transport_resolve(name, &tcfg) == 0)
            snprintf(r->ipc, sizeof(r->ipc), "%s", transport_name(tcfg.kind));
        else
            snprintf(r->ipc, sizeof(r->ipc), "-");
    }
    return 0;
}

/* ---------- formatting ---------- */

static void format_mem(long kb, char *out, size_t n)
{
    if (kb < 0)                       snprintf(out, n, "-");
    else if (kb < 1024)               snprintf(out, n, "%ldkB", kb);
    else if (kb < 1024L * 1024)       snprintf(out, n, "%.1fMB", kb / 1024.0);
    else                              snprintf(out, n, "%.2fGB", kb / (1024.0 * 1024.0));
}

static void format_cpu(double pct, char *out, size_t n)
{
    if (pct < 0)         snprintf(out, n, "-");
    else if (pct < 10.0) snprintf(out, n, "%.2f%%", pct);
    else                 snprintf(out, n, "%.1f%%", pct);
}

static void truncate_to(char *s, size_t max)
{
    if (strlen(s) > max && max >= 3) {
        s[max - 1] = '.';
        s[max - 2] = '.';
        s[max - 3] = '.';
        s[max]     = '\0';
    }
}

static void print_header(void)
{
    printf("%-*s %6s %-*s %6s %7s  %-*s %5s %6s  %-3s %-3s %-3s  %-7s %-6s %4s  %s\n",
           NAME_DISPLAY, "NAME",
           "PID",
           STATE_DISPLAY, "STATE",
           "CPU", "MEM",
           PROFILE_DISPLAY, "PROFILE",
           "TASKS", "ACTIVE",
           "FS", "SC", "CG",
           "IPC",
           "SUP", "RST",
           "GOAL");
}

static void print_row(const struct agent_row *r)
{
    char pidstr[16], cpustr[16], memstr[16];
    if (r->pid > 0) snprintf(pidstr, sizeof(pidstr), "%ld", (long)r->pid);
    else            snprintf(pidstr, sizeof(pidstr), "-");
    format_cpu(r->cpu_pct, cpustr, sizeof(cpustr));
    format_mem(r->mem_kb,  memstr, sizeof(memstr));

    char name_disp[MAX_NAME + 1];
    char prof_disp[MAX_NAME + 1];
    char plan_disp[16];
    char goal_disp[GOAL_DISPLAY + 1];
    snprintf(name_disp, sizeof(name_disp), "%s", r->name);
    snprintf(prof_disp, sizeof(prof_disp), "%s", r->profile[0] ? r->profile : "-");
    snprintf(plan_disp, sizeof(plan_disp), "%s", r->planner[0] ? r->planner : "-");
    snprintf(goal_disp, sizeof(goal_disp), "%s", r->goal[0] ? r->goal : "-");
    truncate_to(name_disp, NAME_DISPLAY);
    truncate_to(prof_disp, PROFILE_DISPLAY);
    truncate_to(plan_disp, PLANNER_DISPLAY);
    truncate_to(goal_disp, GOAL_DISPLAY);

    char taskstr[12], activestr[12];
    snprintf(taskstr,   sizeof(taskstr),   "%d", r->tasks_total);
    snprintf(activestr, sizeof(activestr), "%d", r->tasks_active);

    char rststr[12];
    snprintf(rststr, sizeof(rststr), "%d", r->restart_count);
    (void)plan_disp;  /* dropped from display to make room */

    printf("%-*s %6s %-*s %6s %7s  %-*s %5s %6s  %-3s %-3s %-3s  %-7s %-6s %4s  %s\n",
           NAME_DISPLAY, name_disp,
           pidstr,
           STATE_DISPLAY, r->state,
           cpustr, memstr,
           PROFILE_DISPLAY, prof_disp,
           taskstr, activestr,
           r->fs, r->sc, r->cg,
           r->ipc,
           r->sup, rststr,
           goal_disp);
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    (void)argv;
    if (argc > 1) {
        fputs("usage: psa\n", stderr);
        return 2;
    }
    DIR *d = opendir(AGENT_ROOT);
    if (!d) {
        if (errno == ENOENT) {
            printf("(no agents)\n");
            return 0;
        }
        fprintf(stderr, "psa: %s: %s\n", AGENT_ROOT, strerror(errno));
        return 1;
    }

    int printed = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (validate_name(e->d_name) != 0) continue;
        char dir[MAX_PATHBUF];
        if (snprintf(dir, sizeof(dir), "%s/%s", AGENT_ROOT, e->d_name)
                >= (int)sizeof(dir)) continue;
        struct stat st;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        if (!printed) { print_header(); printed = 1; }
        struct agent_row r;
        if (collect_row(e->d_name, &r) == 0) print_row(&r);
    }
    closedir(d);
    if (!printed) printf("(no agents)\n");
    return 0;
}
