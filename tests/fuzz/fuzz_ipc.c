#include "ipc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > IPC_BUF_CAP) return 0;
    char *frame = malloc(size ? size : 1);
    if (!frame) return 0;
    if (size) memcpy(frame, data, size);
    ipc_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    (void)ipc_parse_for_fuzz(frame, size, &msg);
    free(frame);
    return 0;
}
