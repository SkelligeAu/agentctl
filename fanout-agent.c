
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
#include <time.h>
#include <unistd.h>

#define MAX_TARGETS 16

/* Per-runtime counters for SIGUSR1 snapshot. */
static size_t messages_total      = 0;
static size_t deliveries_total    = 0;
static size_t deliveries_skipped  = 0;
static char   last_verb_seen[MAX_VERB] = "";

/* Parse `caps` for `allow send:<name>` and `deny send:<name>` / `deny send:*`,
 * leaving only the non-denied allowed targets in `targets`. */
static int collect_send_targets(const char *caps_text,
                                char targets[MAX_TARGETS][MAX_NAME])
{
    char denies[MAX_TARGETS][MAX_NAME];
    int n = 0, nd = 0;
    int deny_all = 0;

    const char *p = caps_text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        const char *line = p;
        while (llen > 0 && isspace((unsigned char)*line)) { line++; llen--; }

        const char *kw = NULL;
        size_t kwlen = 0;
        int is_allow = 0;
        if (llen > 5 && strncmp(line, "allow ", 6) == 0) {
            kw = line + 6; kwlen = llen - 6; is_allow = 1;
        } else if (llen > 4 && strncmp(line, "deny ", 5) == 0) {
            kw = line + 5; kwlen = llen - 5; is_allow = 0;
        }
        if (kw) {
            while (kwlen > 0 && isspace((unsigned char)*kw)) { kw++; kwlen--; }
            if (kwlen > 5 && strncmp(kw, "send:", 5) == 0) {
                const char *t = kw + 5;
                size_t tlen = kwlen - 5;
                /* trim trailing whitespace */
                while (tlen > 0 && isspace((unsigned char)t[tlen - 1])) tlen--;
                if (tlen == 1 && t[0] == '*' && !is_allow) {
                    deny_all = 1;
                } else if (tlen > 0 && tlen < MAX_NAME && t[0] != '*') {
                    if (is_allow && n < MAX_TARGETS) {
                        memcpy(targets[n], t, tlen);
                        targets[n][tlen] = '\0';
                        n++;
                    } else if (!is_allow && nd < MAX_TARGETS) {
                        memcpy(denies[nd], t, tlen);
                        denies[nd][tlen] = '\0';
                        nd++;
                    }
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }

    if (deny_all) return 0;
    int out = 0;
    for (int i = 0; i < n; i++) {
        int denied = 0;
        for (int j = 0; j < nd; j++) {
            if (strcmp(targets[i], denies[j]) == 0) { denied = 1; break; }
        }
        if (!denied) {
            if (out != i) memcpy(targets[out], targets[i], MAX_NAME);
            out++;
        }
    }
    return out;
}

int main(int argc, char **argv)
{
    if (refuse_root() != 0) return 1;
    if (argc < 2) { fprintf(stderr, "fanout-agent: missing <name>\n"); return 2; }
    const char *name = argv[1];
    if (validate_name(name) != 0) {
        fprintf(stderr, "fanout-agent: invalid name\n");
        return 2;
    }

    runtime_init();
    runtime_install_signals();

    profile_cfg_t cfg;
    profile_load_for_agent(name, &cfg);

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
    audit_log(name, "fanout-agent started pid=%ld transport=%s profile=%s "
              "dispatch=%s idle_timeout=%d",
              (long)getpid(), transport_name(tcfg.kind), cfg.profile_name,
              dispatch_name(cfg.dispatch),
              cfg.idle_timeout_sec);
    enforcement_audit_status(name);

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
        if (reload_flag) {
            reload_flag = 0;
            do_reload(name);
            profile_load_for_agent(name, &cfg);
        }
        if (rotate_flag) { rotate_flag = 0; do_rotate_artifacts(name); }
        if (snapshot_flag) {
            snapshot_flag = 0;
            char extra[768];
            snprintf(extra, sizeof(extra),
                     "profile: %s\ndispatch: %s\n"
                     "messages_total: %zu\nlast_verb: %s\n"
                     "deliveries_total: %zu\ndeliveries_skipped: %zu\n",
                     cfg.profile_name, dispatch_name(cfg.dispatch),
                     messages_total,
                     last_verb_seen[0] ? last_verb_seen : "-",
                     deliveries_total, deliveries_skipped);
            snapshot_state(name, extra);
        }

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
            if (cfg.dispatch == DISPATCH_SINGLE_SHOT) {
                audit_log(name, "idle %ds; exiting", cfg.idle_timeout_sec);
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

        char caps_text[8192];
        char caps_path[MAX_PATHBUF];
        if (agent_path(caps_path, sizeof(caps_path), name, "policy") != 0 ||
            read_small_file(caps_path, caps_text, sizeof(caps_text), NULL) != 0) {
            caps_text[0] = '\0';
        }

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
        size_t vl = strlen(hdr.verb);
        if (vl >= sizeof(last_verb_seen)) vl = sizeof(last_verb_seen) - 1;
        memcpy(last_verb_seen, hdr.verb, vl);
        last_verb_seen[vl] = '\0';

        if (strcmp(hdr.verb, "ping") == 0) {
            if (client_fd >= 0) {
                char reply[64];
                int rl = snprintf(reply, sizeof(reply),
                                  "pong agent=%s pid=%ld\n", name, (long)getpid());
                if (rl > 0) (void)write_all(client_fd, reply, (size_t)rl);
                close(client_fd);
            }
            continue;
        }

        /* Handle a downstream's `result` reply. TASK-ID identifies our pending
         * delegation; the kernel-verified sender_name identifies which
         * downstream replied. */
        if (strcmp(hdr.verb, "result") == 0) {
            if (client_fd >= 0) close(client_fd);
            if (hdr.task_id[0] == '\0') {
                audit_log(name, "result without TASK-ID dropped");
                continue;
            }
            pending_remove(name, hdr.task_id, sender_name);
            int remaining = pending_count_for_task(name, hdr.task_id);
            audit_log(name, "result task=%s from=%s remaining=%d",
                      hdr.task_id, sender_name, remaining);
            task_append_event(name, hdr.task_id,
                              "reply from=%s remaining=%d", sender_name, remaining);
            if (remaining == 0) {
                task_set_state(name, hdr.task_id, TASK_COMPLETED);
                task_set_status(name, hdr.task_id, "completed");
                task_append_event(name, hdr.task_id, "completed (all downstreams replied)");
            }
            continue;
        }

        /* Close the inbound client now — downstream sends open new
         * connections of their own. (No-op for agentfs.) */
        if (client_fd >= 0) close(client_fd);

        /* Create a task object for this incoming message. */
        char parent_task[MAX_TASK_ID];
        if (task_alloc_id(name, parent_task, sizeof(parent_task)) != 0 ||
            task_create(name, parent_task, hdr.verb, sender_name,
                        peer.pid, peer.uid, hdr.reply_to, hdr.task_id,
                        payload, hdr.payload_len) != 0) {
            audit_log(name, "task_create failed: %s", strerror(errno));
            continue;
        }
        audit_log(name, "task created %s verb=%s from=%s",
                  parent_task, hdr.verb, sender_name);
        task_set_state(name, parent_task, TASK_RUNNING);
        task_set_status(name, parent_task, "running");
        task_append_event(name, parent_task, "running");

        char targets[MAX_TARGETS][MAX_NAME];
        int nt = collect_send_targets(caps_text, targets);
        if (nt == 0) {
            audit_log(name, "no allowed send: targets; verb=%s dropped", hdr.verb);
            task_set_state(name, parent_task, TASK_FAILED);
            task_set_status(name, parent_task, "failed: no send: targets");
            task_append_event(name, parent_task, "failed: no send: targets");
            continue;
        }

        write_status(name, "processing");
        task_set_state(name, parent_task, TASK_DELEGATED);
        task_set_status(name, parent_task, "delegated");
        audit_log(name, "fanout begin verb=%s bytes=%zu targets=%d task=%s",
                  hdr.verb, hdr.payload_len, nt, parent_task);
        task_append_event(name, parent_task,
                          "delegating verb=%s to %d target(s)", hdr.verb, nt);
        int sent = 0, skipped = 0, failed = 0;
        for (int i = 0; i < nt; i++) {
            /* Forward with REPLY-TO=self so the downstream can reply, and
             * TASK-ID=parent_task so we can correlate the reply back to the
             * pending entry. */
            int s = send_to_agent_ex(targets[i], hdr.verb,
                                     name, parent_task,
                                     payload, hdr.payload_len);
            if (s == 0) {
                pending_add(name, parent_task, targets[i]);
                audit_log(name, "delegated task=%s -> %s",
                          parent_task, targets[i]);
                task_append_event(name, parent_task,
                                  "delegated -> %s", targets[i]);
                sent++;
            } else if (s == -2) {
                audit_log(name, "fanout -> %s skipped (no listener)", targets[i]);
                task_append_event(name, parent_task,
                                  "skipped -> %s (no listener)", targets[i]);
                skipped++;
            } else {
                audit_log(name, "fanout -> %s failed: %s",
                          targets[i], strerror(errno));
                task_append_event(name, parent_task,
                                  "failed -> %s: %s", targets[i], strerror(errno));
                failed++;
            }
        }
        deliveries_total   += (size_t)sent;
        deliveries_skipped += (size_t)skipped;
        /* If nothing got delegated, the task is done (failed) right away. */
        if (sent == 0) {
            task_set_state(name, parent_task, TASK_FAILED);
            task_set_status(name, parent_task,
                            "failed: no downstream accepted delegation");
            task_append_event(name, parent_task,
                              "no downstream accepted; task failed");
        }
        audit_log(name, "fanout done sent=%d skipped=%d failed=%d",
                  sent, skipped, failed);
        write_status(name, "idle");
    }

    write_status(name, "stopping");
    audit_log(name, "fanout-agent shutting down");
    close(server_fd);
    if (tcfg.kind == TRANSPORT_UDS) {
        char sock_path[MAX_PATHBUF];
        if (agent_path(sock_path, sizeof(sock_path), name, "agent.sock") == 0)
            (void)unlink(sock_path);
    }
    free(payload);
    write_status(name, "stopped");
    return 0;
}
