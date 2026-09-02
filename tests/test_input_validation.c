#include "broker.h"
#include "tasks.h"

#include <stdio.h>
#include <string.h>

static int expect_rejected(const char *frame)
{
    broker_msg_t msg;
    return broker_parse(frame, strlen(frame), &msg) == -1 ? 0 : -1;
}

int main(void)
{
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
