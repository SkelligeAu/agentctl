/* White-box lifecycle fault tests. Regular files model owned cgroup handles;
 * real kernel cgroup checks are in service_regressions.py. */
#define main agentd_program_main
#include "../agentd.c"
#undef main
#include <assert.h>
#include <sys/resource.h>

static int fixture_fd(const char *text)
{
    char file[] = "/tmp/agentctl-service-fd-XXXXXX";
    int fd = mkstemp(file);
    assert(fd >= 0);
    unlink(file);
    assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    assert(lseek(fd, 0, SEEK_SET) == 0);
    return fd;
}

static struct managed *run_child(int code, enum restart_policy policy)
{
    struct managed *m = alloc_slot("probe");
    assert(m);
    m->run_policy = policy;
    m->timed_out = 0;
    m->cgroup_kill_fd = fixture_fd("");
    m->cgroup_events_fd = fixture_fd("populated 0\nfrozen 0\n");
    m->last_started_at = time(NULL);
    m->pid = fork();
    assert(m->pid >= 0);
    if (!m->pid) _exit(code);
    siginfo_t info;
    assert(waitid(P_PID, (id_t)m->pid, &info, WEXITED | WNOWAIT) == 0);
    return m;
}

int main(void)
{
    char root[] = "/tmp/agentctl-service-test-XXXXXX", dir[MAX_PATHBUF];
    assert(mkdtemp(root));
    assert(setenv("AGENTCTL_ROOT", root, 1) == 0);
    snprintf(dir, sizeof(dir), "%s/agents", root); assert(mkdir(dir, 0700) == 0);
    snprintf(dir, sizeof(dir), "%s/agents/probe", root); assert(mkdir(dir, 0700) == 0);
    assert(agent_ensure_layout("probe") == 0);
    assert(write_agent_setting("probe", "restart_policy", "service") == 0);
    assert(write_agent_setting("probe", "desired_state", "running") == 0);
    struct managed *m = NULL;
    for (int i = 0; i < 25; i++) {
        m = run_child(0, POLICY_SERVICE);
        m->consecutive_failures = 2;
        m->service_admitted = 1;
        reap_zombies();
        assert(m->service_admitted == 0);
        assert(m->pid == 0 && m->consecutive_failures == 0 && m->restart_count == 0);
        assert(load_desired_running("probe") && m->next_restart_at > 0);
    }
    for (int i = 1; i < RESTART_BURST_LIMIT; i++) {
        m = run_child(1, POLICY_SERVICE);
        m->last_started_at = time(NULL) - 30;
        m->service_admitted = 1;
        m->service_admitted_at = time(NULL) - RESTART_STABLE_SEC;
        reap_zombies();
        assert(m->consecutive_failures == i && m->restart_count == i);
        m = run_child(0, POLICY_SERVICE);
        m->run_deadline = monotonic_ms() - 1;
        enforce_service_deadlines(); reap_zombies();
        assert(m->consecutive_failures == i && m->restart_count == i);
        m = run_child(0, POLICY_SERVICE); /* unadmitted exit 0 is not successful work */
        reap_zombies();
        assert(m->consecutive_failures == i && m->restart_count == i);
    }
    pid_t exhausted = fork(); assert(exhausted >= 0);
    if (!exhausted) { run_child(1, POLICY_SERVICE); reap_zombies(); _exit(99); }
    int exhausted_status;
    assert(waitpid(exhausted, &exhausted_status, 0) == exhausted);
    assert(WIFEXITED(exhausted_status) && WEXITSTATUS(exhausted_status) == 70);
    assert(!load_desired_running("probe"));
    release_slot(m);
    assert(write_agent_setting("probe", "desired_state", "running") == 0);
    assert(write_agent_setting("probe", "restart_policy", "always") == 0);
    m = run_child(0, POLICY_ALWAYS); reap_zombies();
    assert(m->consecutive_failures == 1 && m->restart_count == 1);
    release_slot(m);

    m = run_child(0, POLICY_SERVICE);
    m->service_admitted = 1;
    m->run_deadline = monotonic_ms() - 1;
    enforce_service_deadlines();
    assert(m->timed_out && m->run_deadline == 0);
    reap_zombies();
    assert(m->consecutive_failures == 1); /* deadline wins even an exit-0 race */
    release_slot(m);

    m = run_child(0, POLICY_SERVICE);
    m->run_deadline = monotonic_ms() - 1;
    enforce_service_deadlines(); reap_zombies();
    assert(m->restart_count == 0 && m->consecutive_failures == 0);
    assert(load_desired_running("probe"));
    release_slot(m);

    /* Real socketpair delivery; no kernel cgroup authority is simulated here. */
    int inbox[2], offered = -1;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, inbox) == 0);
    m = alloc_slot("probe");
    m->pid = getpid(); m->inbox_fd = inbox[0]; m->run_policy = POLICY_SERVICE;
    m->run_deadline = monotonic_ms() + 250; /* near the idle limit */
    m->service_request_timeout_ms = 6000;
    long long before = monotonic_ms();
    assert(issue_mailbox_channel("sender", getpid(), getuid(), "probe", &offered) == 0);
    assert(m->service_admitted == 1 && m->run_deadline >= before + 6000);
    close(offered);
    long long admitted_deadline = m->run_deadline;
    assert(issue_mailbox_channel("sender", getpid(), getuid(), "probe", &offered) == -3);
    assert(m->run_deadline == admitted_deadline);
    close(inbox[1]);
    clear_runtime_state(m);
    assert(m->service_admitted == 0 && m->run_deadline == 0);
    release_slot(m);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, inbox) == 0);
    m = alloc_slot("probe");
    m->pid = getpid(); m->inbox_fd = inbox[0]; m->run_policy = POLICY_SERVICE;
    m->run_deadline = monotonic_ms() + 250;
    m->service_request_timeout_ms = 6000;
    close(inbox[1]); /* Inject a failed inbox transfer. */
    assert(issue_mailbox_channel("sender", getpid(), getuid(), "probe", &offered) < 0);
    assert(m->service_admitted == 1 && m->run_deadline <= monotonic_ms());
    assert(issue_mailbox_channel("sender", getpid(), getuid(), "probe", &offered) == -3);
    release_slot(m);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, inbox) == 0);
    m = alloc_slot("probe");
    m->pid = getpid(); m->inbox_fd = inbox[0]; m->run_policy = POLICY_ALWAYS;
    for (int i = 0; i < 2; i++) {
        assert(issue_mailbox_channel("sender", getpid(), getuid(), "probe", &offered) == 0);
        close(offered);
        assert(m->service_admitted == 0 && m->run_deadline == 0);
    }
    close(inbox[1]); release_slot(m);

    m = alloc_slot("probe");
    m->pid = 999999; m->run_policy = POLICY_SERVICE;
    m->cgroup_kill_fd = fixture_fd("");
    m->cgroup_events_fd = fixture_fd("populated 1\n");
    pid_t test = fork(); assert(test >= 0);
    if (!test) { kill_remaining_children(m); _exit(99); }
    int status; assert(waitpid(test, &status, 0) == test);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 70);
    close(m->cgroup_kill_fd); m->cgroup_kill_fd = -1;
    test = fork(); assert(test >= 0);
    if (!test) { kill_remaining_children(m); _exit(99); }
    assert(waitpid(test, &status, 0) == test);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 70);
    release_slot(m);
    assert(write_agent_setting("probe", "exec", "/bin/true") == 0);
    assert(write_agent_setting("probe", "restart_policy", "service") == 0);
    const char *invalid[] = {"0", "-1", "86400001", "30oops"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        assert(write_agent_setting("probe", "desired_state", "running") == 0);
        assert(write_agent_setting("probe", "service_timeout_ms", invalid[i]) == 0);
        m = alloc_slot("probe");
        assert(spawn_agent(m) == -1 && errno == EINVAL);
        assert(!load_desired_running("probe") && m->pid == 0);
        release_slot(m);
    }
    assert(write_agent_setting("probe", "service_timeout_ms", "30000") == 0);
    m = alloc_slot("probe");
    assert(spawn_agent(m) == -1 && errno == EINVAL); /* request timeout required */
    release_slot(m);
    assert(write_agent_setting("probe", "service_request_timeout_ms", "0") == 0);
    m = alloc_slot("probe");
    assert(spawn_agent(m) == -1 && errno == EINVAL);
    release_slot(m);
    assert(write_agent_setting("probe", "critical", "yes") == 0);
    test = fork(); assert(test >= 0);
    if (!test) { m = alloc_slot("probe"); spawn_agent(m); _exit(99); }
    assert(waitpid(test, &status, 0) == test);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 70);
    test = fork(); assert(test >= 0);
    if (!test) { m = run_child(0, POLICY_NEVER); m->critical = 1; reap_zombies(); _exit(99); }
    assert(waitpid(test, &status, 0) == test);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 70);
    test = fork(); assert(test >= 0);
    if (!test) {
        assert(setup_signals() == 0);
        struct sigaction action;
        assert(sigaction(SIGXFSZ, NULL, &action) == 0 && action.sa_handler == on_signal);
#ifdef __linux__
        struct rlimit limit = {16, 16};
        assert(setrlimit(RLIMIT_FSIZE, &limit) == 0);
        daemon_log("force audit storage limit failure");
#else
        /* macOS returns EFBIG without delivering SIGXFSZ for this append.
         * Verify registration/dispatch here; Linux verifies real overflow. */
        assert(raise(SIGXFSZ) == 0);
#endif
        _exit(99);
    }
    assert(waitpid(test, &status, 0) == test);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 70);
    puts("PASS: service lifecycle, admission, fail-closed cleanup and log-size limit");
    return 0;
}
