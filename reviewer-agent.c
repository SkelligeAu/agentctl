#include "common.h"
#include "enforcement.h"
#include "profiles.h"
#include "tasks.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Per-runtime counters surfaced via SIGUSR1 snapshot. */
static size_t messages_total = 0;
static char   last_verb_seen[MAX_VERB] = "";
static time_t last_message_at = 0;

struct pattern { const char *needle; const char *sev; };
static const struct pattern PATTERNS[] = {
    { "TODO",     "low"  },
    { "FIXME",    "low"  },
    { "password", "high" },
    { "secret",   "high" },
    { "eval",     "med"  },
    { "strcpy",   "high" },
    { "gets",     "high" },
};
#define NPATTERNS (sizeof(PATTERNS) / sizeof(PATTERNS[0]))

static size_t count_pattern(const char *hay, size_t n, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || nl > n) return 0;
    size_t count = 0;
    for (size_t i = 0; i + nl <= n; i++) {
        if (memcmp(hay + i, needle, nl) == 0) count++;
    }
    return count;
}

static void count_diff(const char *buf, size_t n, size_t *added, size_t *removed)
{
    *added = 0; *removed = 0;
    int at_line_start = 1;
    size_t i = 0;
    while (i < n) {
        if (at_line_start) {
            int is_plus_header  = (i + 2 < n && buf[i] == '+' && buf[i+1] == '+' && buf[i+2] == '+');
            int is_minus_header = (i + 2 < n && buf[i] == '-' && buf[i+1] == '-' && buf[i+2] == '-');
            if (!is_plus_header && !is_minus_header) {
                if (buf[i] == '+') (*added)++;
                else if (buf[i] == '-') (*removed)++;
            }
        }
        at_line_start = (buf[i] == '\n');
        i++;
    }
}

static int write_review_md(const char *name, const char *task_id, size_t plen,
                           size_t added, size_t removed,
                           const size_t counts[NPATTERNS],
                           artifact_policy_t policy)
{
    size_t cap = 64 * 1024;
    char *buf = malloc(cap);
    if (!buf) return -1;
    size_t pos = 0;
    int w;
#define APP(...) do { \
    w = snprintf(buf + pos, cap - pos, __VA_ARGS__); \
    if (w < 0 || (size_t)w >= cap - pos) { free(buf); return -1; } \
    pos += (size_t)w; \
} while (0)
    APP("# Review\n\n");
    APP("- payload bytes: %zu\n", plen);
    APP("- lines added:   %zu\n", added);
    APP("- lines removed: %zu\n\n", removed);
    APP("## Findings\n\n");
    APP("| Pattern | Count | Severity |\n");
    APP("|---|---:|---|\n");
    size_t total = 0, high = 0;
    for (size_t i = 0; i < NPATTERNS; i++) {
        APP("| %s | %zu | %s |\n", PATTERNS[i].needle, counts[i], PATTERNS[i].sev);
        total += counts[i];
        if (strcmp(PATTERNS[i].sev, "high") == 0) high += counts[i];
    }
    APP("\n## Summary\n\n");
    APP("%zu findings total; %zu high-severity.\n", total, high);
#undef APP
    int r = task_write_artifact(name, task_id, "review.md", buf, pos, policy);
    free(buf);
    return r;
}

static int write_risks_json(const char *name, const char *task_id,
                            size_t added, size_t removed,
                            const size_t counts[NPATTERNS],
                            artifact_policy_t policy)
{
    char buf[4096];
    size_t pos = 0;
    int w;
#define APP(...) do { \
    w = snprintf(buf + pos, sizeof(buf) - pos, __VA_ARGS__); \
    if (w < 0 || (size_t)w >= sizeof(buf) - pos) return -1; \
    pos += (size_t)w; \
} while (0)
    APP("{\n  \"added\": %zu,\n  \"removed\": %zu,\n  \"findings\": [\n",
        added, removed);
    int first = 1;
    for (size_t i = 0; i < NPATTERNS; i++) {
        if (counts[i] == 0) continue;
        APP("%s    {\"pattern\":\"%s\",\"count\":%zu,\"severity\":\"%s\"}",
            first ? "" : ",\n", PATTERNS[i].needle, counts[i], PATTERNS[i].sev);
        first = 0;
    }
    APP("%s  ]\n}\n", first ? "" : "\n");
#undef APP
    return task_write_artifact(name, task_id, "risks.json", buf, pos, policy);
}

static int write_patch_suggestions(const char *name, const char *task_id,
                                   const char *payload, size_t plen,
                                   artifact_policy_t policy)
{
    return task_write_artifact(name, task_id, "patch-suggestions.diff",
                               payload, plen, policy);
}

/* Returns 0 on success, -1 on failure. Writes a short summary to tasks/<id>/result.
 *
 * NOTE: artifact write authority is no longer self-gated against the caps
 * file. In the v1 broker world capabilities are fds (issued by agentd).
 * Pre-exec wiring of artifact dirfd is on the roadmap; until it lands,
 * artifact writes are gated by Landlock + the agent's profile. */
static int handle_review(const char *name, const char *task_id,
                         const char *payload, size_t plen,
                         artifact_policy_t policy,
                         char *summary_out, size_t summary_n)
{
    write_status(name, "processing");
    task_append_event(name, task_id, "review begin policy=%s",
                      artifact_policy_name(policy));

    size_t added = 0, removed = 0;
    count_diff(payload, plen, &added, &removed);

    size_t counts[NPATTERNS];
    for (size_t i = 0; i < NPATTERNS; i++)
        counts[i] = count_pattern(payload, plen, PATTERNS[i].needle);

    int rc;
    if ((rc = write_review_md(name, task_id, plen, added, removed, counts, policy)) != 0) {
        audit_log(name, "review error: review.md: %s", strerror(errno));
    } else if ((rc = write_risks_json(name, task_id, added, removed, counts, policy)) != 0) {
        audit_log(name, "review error: risks.json: %s", strerror(errno));
    } else if ((rc = write_patch_suggestions(name, task_id, payload, plen, policy)) != 0) {
        audit_log(name, "review error: patch-suggestions: %s", strerror(errno));
    }
    size_t findings = counts[0]+counts[1]+counts[2]+counts[3]+counts[4]+counts[5]+counts[6];
    if (rc == 0) {
        audit_log(name, "review done added=%zu removed=%zu findings=%zu",
                  added, removed, findings);
        task_append_event(name, task_id,
                          "review done added=%zu removed=%zu findings=%zu",
                          added, removed, findings);
        snprintf(summary_out, summary_n,
                 "status: completed\nadded: %zu\nremoved: %zu\nfindings: %zu\n",
                 added, removed, findings);
    } else {
        snprintf(summary_out, summary_n,
                 "status: failed\nreason: %s\n", strerror(errno));
    }
    write_status(name, "idle");
    return rc;
}

int main(int argc, char **argv)
{
    if (refuse_root() != 0) return 1;
    if (argc < 2) { fprintf(stderr, "reviewer-agent: missing <name>\n"); return 2; }
    const char *name = argv[1];
    if (validate_name(name) != 0) {
        fprintf(stderr, "reviewer-agent: invalid name\n");
        return 2;
    }

    runtime_init();
    runtime_install_signals();

    profile_cfg_t cfg;
    profile_load_for_agent(name, &cfg);

    /* Resolve the IPC substrate. Default UDS; switches to agentfs if the
     * agent's transport file says so. The runtime above this point is
     * transport-agnostic — only the listener setup + accept/read branch
     * below cares. */
    transport_cfg_t tcfg;
    transport_resolve(name, &tcfg);

    int server_fd;
    if (tcfg.kind == TRANSPORT_AGENTFS) {
        server_fd = agentfs_listen(name, tcfg.mount);
        if (server_fd == -1) {
            audit_log(name, "agentfs_listen(%s) failed: %s",
                      tcfg.mount, strerror(errno));
            return 1;
        }
    } else {
        server_fd = create_server_socket(name);
        if (server_fd == -1) {
            audit_log(name, "create_server_socket failed: %s", strerror(errno));
            return 1;
        }
    }

    write_status(name, "idle");
    audit_log(name, "reviewer-agent started pid=%ld transport=%s profile=%s "
              "dispatch=%s artifact_policy=%s idle_timeout=%d",
              (long)getpid(), transport_name(tcfg.kind), cfg.profile_name,
              dispatch_name(cfg.dispatch),
              artifact_policy_name(cfg.artifact_policy), cfg.idle_timeout_sec);
    enforcement_audit_status(name);

    /* Recovery: any task left in queued/running/delegated died with the
     * previous instance. Mark them failed and audit the count. */
    {
        int n = task_recover_interrupted(name);
        if (n > 0) audit_log(name, "recovery: marked %d interrupted task(s) failed", n);
    }

    void *payload = malloc(MAX_PAYLOAD);
    if (!payload) {
        audit_log(name, "oom allocating payload buffer");
        close(server_fd);
        return 1;
    }

    while (!shutdown_flag) {
        /* Drain pending signal flags before blocking on accept again. */
        if (reload_flag)   {
            reload_flag = 0;
            do_reload(name);
            /* Reload the profile too. */
            profile_load_for_agent(name, &cfg);
        }
        if (rotate_flag)   { rotate_flag = 0;   do_rotate_artifacts(name); }
        if (snapshot_flag) {
            snapshot_flag = 0;
            char extra[768];
            char last_at[32] = "-";
            if (last_message_at) {
                struct tm tm; gmtime_r(&last_message_at, &tm);
                snprintf(last_at, sizeof(last_at),
                         "%04d-%02d-%02dT%02d:%02d:%02dZ",
                         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                         tm.tm_hour, tm.tm_min, tm.tm_sec);
            }
            snprintf(extra, sizeof(extra),
                     "profile: %s\ndispatch: %s\nartifact_policy: %s\n"
                     "messages_total: %zu\nlast_verb: %s\nlast_message_at: %s\n",
                     cfg.profile_name, dispatch_name(cfg.dispatch),
                     artifact_policy_name(cfg.artifact_policy),
                     messages_total,
                     last_verb_seen[0] ? last_verb_seen : "-",
                     last_at);
            snapshot_state(name, extra);
        }

        /* poll() so we can honour idle_timeout. */
        struct pollfd pfd = { server_fd, POLLIN, 0 };
        int timeout_ms = (cfg.idle_timeout_sec > 0)
                            ? cfg.idle_timeout_sec * 1000 : -1;
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr == -1) {
            if (errno == EINTR && shutdown_flag) break;
            if (errno == EINTR) continue;
            audit_log(name, "poll error: %s", strerror(errno));
            continue;
        }
        if (pr == 0) {
            /* idle timeout. single-shot dispatch exits; others just loop. */
            if (cfg.dispatch == DISPATCH_SINGLE_SHOT) {
                audit_log(name, "idle %ds; exiting (dispatch=single-shot)",
                          cfg.idle_timeout_sec);
                break;
            }
            continue;
        }

        agent_msg_hdr hdr;
        peer_id_t peer;
        memset(&peer, 0, sizeof(peer));
        char sender_name[MAX_NAME] = "-";
        int client_fd = -1;

        if (tcfg.kind == TRANSPORT_AGENTFS) {
            /* Datagram-style: one read returns one full framed message.
             * No per-message peer creds (kernel doesn't track who wrote);
             * we use REPLY-TO as a sender hint, which is a userspace
             * claim, not a kernel-verified identity. */
            int r = agentfs_recv(server_fd, &hdr, payload);
            if (r != 0) {
                int e = errno;
                if (e == EINTR && shutdown_flag) break;
                if (e == EINTR) continue;
                audit_log(name, "agentfs_recv error: %s", strerror(e));
                continue;
            }
            if (hdr.reply_to[0])
                snprintf(sender_name, sizeof(sender_name), "%s", hdr.reply_to);
            else
                snprintf(sender_name, sizeof(sender_name), "?");
        } else {
            client_fd = accept_client(server_fd, &peer);
            if (client_fd == -1) {
                int e = errno;
                if (e == EINTR && shutdown_flag) break;
                if (e == EINTR) continue;
                audit_log(name, "accept error: %s", strerror(e));
                continue;
            }
            if (peer.authenticated_name[0]) {
                snprintf(sender_name, sizeof(sender_name), "%s",
                         peer.authenticated_name);
            } else if (peer.pid > 0) {
                if (resolve_agent_by_pid(peer.pid, sender_name, sizeof(sender_name)) != 0)
                    snprintf(sender_name, sizeof(sender_name), "?");
            }
            int r = read_message(client_fd, &hdr, payload);
            if (r != 0) {
                audit_log(name, "recv error from=%s pid=%ld uid=%ld: %s",
                          sender_name, (long)peer.pid, (long)peer.uid, strerror(errno));
                close(client_fd);
                continue;
            }
        }

        /* Re-read caps each message — supports dynamic grant/deny. */
        char caps_text[8192];
        char caps_path[MAX_PATHBUF];
        if (agent_path(caps_path, sizeof(caps_path), name, "policy") != 0 ||
            read_small_file(caps_path, caps_text, sizeof(caps_text), NULL) != 0) {
            caps_text[0] = '\0';
        }

        /* Receiver-side authorization: deny-list. */
        if (recv_is_denied(caps_text, sender_name)) {
            audit_log(name, "reject verb=%s from=%s pid=%ld uid=%ld (deny recv:)",
                      hdr.verb, sender_name, (long)peer.pid, (long)peer.uid);
            if (client_fd >= 0) close(client_fd);
            continue;
        }

        audit_log(name, "recv verb=%s from=%s pid=%ld uid=%ld len=%zu",
                  hdr.verb, sender_name, (long)peer.pid, (long)peer.uid,
                  hdr.payload_len);

        messages_total++;
        last_message_at = time(NULL);
        size_t vl = strlen(hdr.verb);
        if (vl >= sizeof(last_verb_seen)) vl = sizeof(last_verb_seen) - 1;
        memcpy(last_verb_seen, hdr.verb, vl);
        last_verb_seen[vl] = '\0';

        if (strcmp(hdr.verb, "ping") == 0) {
            /* Health probe — no task created. On UDS we can reply over the
             * same socket; on agentfs there's no per-message back-channel
             * (the kernel mailbox is one-way). */
            if (client_fd >= 0) {
                char reply[64];
                int rl = snprintf(reply, sizeof(reply),
                                  "pong agent=%s pid=%ld\n", name, (long)getpid());
                if (rl > 0) (void)write_all(client_fd, reply, (size_t)rl);
                close(client_fd);
            }
            continue;
        }

        /* Create a task object for this message. */
        char task_id[MAX_TASK_ID];
        if (task_alloc_id(name, task_id, sizeof(task_id)) != 0 ||
            task_create(name, task_id, hdr.verb, sender_name,
                        peer.pid, peer.uid, hdr.reply_to, hdr.task_id,
                        payload, hdr.payload_len) != 0) {
            audit_log(name, "task_create failed: %s", strerror(errno));
            if (client_fd >= 0) close(client_fd);
            continue;
        }
        audit_log(name, "task created %s verb=%s from=%s",
                  task_id, hdr.verb, sender_name);
        task_set_state(name, task_id, TASK_RUNNING);
        task_set_status(name, task_id, "running");
        task_append_event(name, task_id, "running");

        char summary[256] = "";
        int task_rc = -1;
        if (strcmp(hdr.verb, "review") == 0) {
            task_rc = handle_review(name, task_id,
                                    (const char *)payload, hdr.payload_len,
                                    cfg.artifact_policy,
                                    summary, sizeof(summary));
        } else {
            audit_log(name, "unknown verb: %s", hdr.verb);
            task_append_event(name, task_id, "unknown verb");
            snprintf(summary, sizeof(summary),
                     "status: failed\nreason: unknown verb %s\n", hdr.verb);
            task_rc = -1;
        }

        /* Persist result file. */
        {
            char rpath[MAX_PATHBUF];
            char rel[64];
            snprintf(rel, sizeof(rel), "tasks/%s/result", task_id);
            if (agent_path(rpath, sizeof(rpath), name, rel) == 0) {
                (void)atomic_write_file(rpath, summary, strlen(summary), 0600);
            }
        }

        if (task_rc == 0) {
            task_set_state(name, task_id, TASK_COMPLETED);
            task_set_status(name, task_id, "completed");
            task_append_event(name, task_id, "completed");
        } else {
            task_set_state(name, task_id, TASK_FAILED);
            task_set_status(name, task_id, "failed");
            task_append_event(name, task_id, "failed");
        }

        /* Close inbound BEFORE replying. Otherwise the supervisor is still
         * stuck in its half-close drain waiting for us to close, while we'd
         * be stuck connecting back to it — both hit the 1s drain timeout.
         * (No-op for agentfs; the kernel mailbox has no inbound fd.) */
        if (client_fd >= 0) close(client_fd);

        if (hdr.reply_to[0] != '\0') {
            const char *corr = hdr.task_id[0] ? hdr.task_id : task_id;
            int s = send_to_agent_ex(hdr.reply_to, "result", NULL, corr,
                                     summary, strlen(summary));
            if (s == 0) {
                audit_log(name, "reply -> %s ok (task=%s)", hdr.reply_to, corr);
                task_append_event(name, task_id, "reply sent -> %s", hdr.reply_to);
            } else if (s == -2) {
                audit_log(name, "reply -> %s skipped (no listener)", hdr.reply_to);
                task_append_event(name, task_id, "reply -> %s skipped", hdr.reply_to);
            } else {
                audit_log(name, "reply -> %s failed: %s",
                          hdr.reply_to, strerror(errno));
                task_append_event(name, task_id, "reply -> %s failed: %s",
                                  hdr.reply_to, strerror(errno));
            }
        }

        if (cfg.dispatch == DISPATCH_SINGLE_SHOT) {
            audit_log(name, "single-shot: task %s done, exiting", task_id);
            break;
        }
    }

    write_status(name, "stopping");
    audit_log(name, "reviewer-agent shutting down");
    close(server_fd);
    if (tcfg.kind == TRANSPORT_UDS) {
        char sock_path[MAX_PATHBUF];
        if (agent_path(sock_path, sizeof(sock_path), name, "agent.sock") == 0)
            (void)unlink(sock_path);
    }
    /* For agentfs: closing the inbox fd is enough. The kernel reaper will
     * notice we exited and flip status=dead within REAPER_INTERVAL_MS. */
    free(payload);
    write_status(name, "stopped");
    return 0;
}
