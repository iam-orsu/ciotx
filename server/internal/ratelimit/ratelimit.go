// Package ratelimit provides a per-key concurrency limiter.
// It caps the number of simultaneous operations for any string key —
// no external dependencies, safe for concurrent use.
package ratelimit

import (
	"sync"
	"sync/atomic"
)

// ConcurrencyLimiter enforces a maximum number of concurrent operations per key.
type ConcurrencyLimiter struct {
	counts sync.Map // key (string) -> *int64 counter
	max    int64
}

// New returns a limiter allowing at most max concurrent operations per key.
func New(max int64) *ConcurrencyLimiter {
	if max < 1 {
		max = 1
	}
	return &ConcurrencyLimiter{max: max}
}

// Acquire attempts to claim a slot for key.
// Returns true on success; false if the key is already at its limit.
// Every successful Acquire must be paired with exactly one Release.
func (l *ConcurrencyLimiter) Acquire(key string) bool {
	actual, _ := l.counts.LoadOrStore(key, new(int64))
	counter := actual.(*int64)
	n := atomic.AddInt64(counter, 1)
	if n > l.max {
		atomic.AddInt64(counter, -1)
		return false
	}
	return true
}

// Release frees a slot for key.
// Must be called exactly once after each successful Acquire.
func (l *ConcurrencyLimiter) Release(key string) {
	if v, ok := l.counts.Load(key); ok {
		atomic.AddInt64(v.(*int64), -1)
	}
}

// Count returns the current number of active slots for key.
// Intended for tests and diagnostics only.
func (l *ConcurrencyLimiter) Count(key string) int64 {
	if v, ok := l.counts.Load(key); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}
