package gateway

import (
	"container/heap"
	"net"
	"net/http"
	"sync"
	"time"
)

// Pairing abuse limits (spec §6.2, §6.3, §6.4).
const (
	// AuthorizePerMinute bounds device authorizations per client address.
	AuthorizePerMinute = 60
	// MaxPendingPerTenant bounds live pending pairings of one tenant.
	MaxPendingPerTenant = 1000
	// MaxSlowDowns ends a device_code that keeps polling too fast: after this
	// many slow_down answers the code expires (expired_token).
	MaxSlowDowns = 10
	// FailuresPerMinute bounds failed pairing decisions per end user.
	FailuresPerMinute = 10
	initialInterval   = 2
)

// jtiCache remembers proof and assertion jtis until they expire. Lookups
// and inserts are O(log n): expired entries leave from the top of a
// min-heap ordered by expiry, never by scanning the whole set, and the
// cache has its own lock (the gateway lock is not held).
type jtiCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	exp  jtiHeap
}

type jtiEntry struct {
	jti string
	at  time.Time
}

type jtiHeap []jtiEntry

func (h jtiHeap) Len() int           { return len(h) }
func (h jtiHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h jtiHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *jtiHeap) Push(x any)        { *h = append(*h, x.(jtiEntry)) }
func (h *jtiHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

func newJTICache() *jtiCache { return &jtiCache{seen: map[string]time.Time{}} }

func (c *jtiCache) evictLocked(now time.Time) {
	for len(c.exp) > 0 && now.After(c.exp[0].at) {
		e := heap.Pop(&c.exp).(jtiEntry)
		if at, ok := c.seen[e.jti]; ok && !at.After(e.at) {
			delete(c.seen, e.jti)
		}
	}
}

// Seen reports whether j is a live (unexpired) jti.
func (c *jtiCache) Seen(j string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked(time.Now())
	_, ok := c.seen[j]
	return ok
}

// Use records j until `until`; false if it was already recorded.
func (c *jtiCache) Use(j string, until time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked(time.Now())
	if _, ok := c.seen[j]; ok {
		return false
	}
	c.seen[j] = until
	heap.Push(&c.exp, jtiEntry{j, until})
	return true
}

// Len is the number of remembered jtis.
func (c *jtiCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// windowCounter counts events per key in fixed one-minute windows; the
// whole map is dropped when the window rolls over, so it never outgrows one
// minute of keys.
type windowCounter struct {
	mu    sync.Mutex
	start time.Time
	n     map[string]int
}

func (w *windowCounter) allow(key string, limit int, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n == nil || now.Sub(w.start) >= time.Minute {
		w.start, w.n = now, map[string]int{}
	}
	if w.n[key] >= limit {
		return false
	}
	w.n[key]++
	return true
}

// clientAddr is the peer address of a request (the TCP peer; forwarding
// headers are not trusted).
func clientAddr(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
