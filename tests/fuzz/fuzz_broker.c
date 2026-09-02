#include "broker.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    broker_msg_t msg;
    (void)broker_parse((const char *)data, size, &msg);
    return 0;
}
