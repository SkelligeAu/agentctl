#include "common.h"

#include <time.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    write_status(argv[1], "idle");
    struct timespec ts = { 0, 200L * 1000L * 1000L };
    nanosleep(&ts, NULL);
    return 1;
}
