#include <stdint.h>
#include <time.h>

extern "C" uint64_t vddpi_clock_ns() {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) != 0) return 0;
    return uint64_t(t.tv_sec) * UINT64_C(1000000000) + uint64_t(t.tv_nsec);
}
