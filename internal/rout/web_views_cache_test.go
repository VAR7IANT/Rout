package rout

import (
	"sync"
	"testing"
)

// An invalidation that lands while a lookup is running (a node listing racing a start/stop
// request) used to leave the map nil and panic while the mutex was held.
func TestServiceCacheInvalidatedDuringLookup(t *testing.T) {
	var c serviceCache
	got := c.get("k", func() string {
		c.invalidate()
		return "running"
	})
	if got != "running" {
		t.Fatalf("got %q", got)
	}
	// The answer predates the invalidation, so it must not be cached...
	calls := 0
	if v := c.get("k", func() string { calls++; return "stopped" }); v != "stopped" || calls != 1 {
		t.Fatalf("stale value cached: %q calls=%d", v, calls)
	}
	// ...and the mutex is free.
	c.invalidate()
}

func TestServiceCacheConcurrentUse(t *testing.T) {
	var c serviceCache
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				if j%7 == i%7 {
					c.invalidate()
				}
				c.get("k", func() string { return "running" })
			}
		}(i)
	}
	wg.Wait()
}
