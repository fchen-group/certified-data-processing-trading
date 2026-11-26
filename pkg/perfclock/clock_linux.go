//go:build linux && cgo

// Package perfclock supplies performance timestamps, never security decisions.
package perfclock

/*
#include <stdint.h>
#include <time.h>
static int64_t work2_perf_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
*/
import "C"

import "time"

// EGo maps CLOCK_MONOTONIC to a coarse vDSO clock (~4 ms). RAW uses
// the host clock through an OCALL; native Linux uses the same clock ID.
// The host clock is untrusted and is used only in the experiment environment.
const Source = "clock_monotonic_raw"

func Now() time.Duration {
	n := int64(C.work2_perf_now())
	if n < 0 {
		panic("performance clock unavailable")
	}
	return time.Duration(n)
}

func Since(start time.Duration) time.Duration { return Now() - start }
