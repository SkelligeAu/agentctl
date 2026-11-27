#include "broker.h"
#include "tasks.h"
#include "enforcement.h"
#include "profiles.h"

#include <stdio.h>
#include <string.h>

static int expect_rejected(const char *frame)
{
    broker_msg_t msg;
    return broker_parse(frame, strlen(frame), &msg) == -1 ? 0 : -1;
}

int main(void)
{
    profile_cfg_t profile;
    memset(&profile, 0xa5, sizeof(profile));
    if (profile_load_by_name("missing-test-default-profile", &profile) != -1 ||
        profile.cgroup_memory_max != 0 || profile.cgroup_pids_max != 0 ||
        profile.cgroup_cpu_max[0] != '\0') {
        fputs("FAIL: unset profile limits must be initialized\n", stderr); return 1;
    }
    char quota[64];
    const char *valid[][2] = {
        {"10000/100000", "10000 100000"},
        {"max/100000", "max 100000"},
        {"1000/1000", "1000 1000"},
        {"1000000/1000000", "1000000 1000000"},
        {"01000/01000", "1000 1000"}
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        if (enforcement_cpu_max_format(valid[i][0], quota, sizeof(quota)) != 0 ||
            strcmp(quota, valid[i][1])) {
            fprintf(stderr, "FAIL: valid CPU quota %s\n", valid[i][0]); return 1;
        }
    }
    const char *invalid[] = {"", "garbage", "10000", "10000/", "/100000",
        "0/100000", "-10000/100000", "+10000/100000", "999/100000",
        "1000/999", "1000/1000001", "max/0", "1000/1000/junk",
        "1000/1000junk", "1000/1000 1", "18446744073709551616/100000",
        "1000/18446744073709551616", "18446744073709551615/100000"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        if (enforcement_cpu_max_format(invalid[i], quota, sizeof(quota)) == 0) {
            fprintf(stderr, "FAIL: invalid CPU quota accepted: %s\n", invalid[i]); return 1;
        }
    }
    if (enforcement_cpu_max_format("1000/1000", quota, 2) == 0) return 1;
    if (task_validate_id("20260902T120000Z-0001") != 0 ||
        task_validate_id("../escape") == 0 ||
        task_validate_id("a/b") == 0 ||
        task_validate_id(".hidden") == 0) {
        fputs("FAIL: task id validation\n", stderr);
        return 1;
    }
    if (task_validate_artifact_name("review.md") != 0 ||
        task_validate_artifact_name("../review.md") == 0 ||
        task_validate_artifact_name("dir/review.md") == 0) {
        fputs("FAIL: artifact name validation\n", stderr);
        return 1;
    }
    if (expect_rejected("VERB request\nCAP one\nCAP two\n\n") != 0 ||
        expect_rejected("VERB request\nVERB denied\nCAP one\n\n") != 0 ||
        expect_rejected("VERB request\nCAP one\n") != 0 ||
        expect_rejected("VERB request\n\n") != 0) {
        fputs("FAIL: ambiguous broker frame accepted\n", stderr);
        return 1;
    }

    char oversized[BROKER_CAP_MAX + 64];
    int n = snprintf(oversized, sizeof(oversized), "VERB request\nCAP %0*d\n\n",
                     BROKER_CAP_MAX + 1, 0);
    if (n <= 0 || (size_t)n >= sizeof(oversized) ||
        expect_rejected(oversized) != 0) {
        fputs("FAIL: oversized broker field accepted or test setup failed\n", stderr);
        return 1;
    }

    puts("PASS: path components and broker fields fail closed");
    return 0;
}
