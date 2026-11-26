#include <stdint.h>
#include <time.h>
#include <cstdlib>
extern "C" uint64_t work2_diag_now() {
    timespec t{};if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))abort();
    return uint64_t(t.tv_sec)*UINT64_C(1000000000)+uint64_t(t.tv_nsec);
}
