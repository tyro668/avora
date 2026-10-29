package gateway

import (
	"fmt"
	"testing"
	"time"
)

// P2-2: the jti store forgets entries at their expiry and never scans the
// whole set: with 200k live entries an insert costs microseconds, not the
// ~1.5 ms per call (under the global lock) of the old full sweep.
func TestJTICacheBoundedAndFast(t *testing.T) {
	c := newJTICache()
	now := time.Now()
	for i := 0; i < 200000; i++ {
		c.Use(fmt.Sprint("live", i), now.Add(time.Hour))
	}
	for i := 0; i < 1000; i++ {
		c.Use(fmt.Sprint("short", i), now.Add(-time.Second)) // already expired
	}
	st := time.Now()
	for i := 0; i < 1000; i++ {
		if !c.Use(fmt.Sprint("new", i), now.Add(time.Minute)) {
			t.Fatal("fresh jti refused")
		}
	}
	per := time.Since(st) / 1000
	if per > 200*time.Microsecond {
		t.Fatalf("Use with 200k live entries: %v per call", per)
	}
	if c.Use("live7", now.Add(time.Hour)) || !c.Seen("live7") {
		t.Fatal("replayed jti accepted")
	}
	if n := c.Len(); n != 201000 {
		t.Fatalf("expired entries kept: %d", n)
	}
}
