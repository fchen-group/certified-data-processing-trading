package perfclock

import (
	"testing"
	"time"
)

func TestElapsed(t *testing.T) {
	start := Now()
	prev := start
	for i := 0; i < 1000; i++ {
		n := Now()
		if n < prev {
			t.Fatal("performance clock moved backwards")
		}
		prev = n
	}
	time.Sleep(20 * time.Millisecond)
	if elapsed := Since(start); elapsed < 15*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("unexpected elapsed time: %s", elapsed)
	}
}
