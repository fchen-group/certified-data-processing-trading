//go:build !linux || !cgo

package perfclock

import "time"

const Source = "go_monotonic"

var origin = time.Now()

func Now() time.Duration                      { return time.Since(origin) }
func Since(start time.Duration) time.Duration { return Now() - start }
