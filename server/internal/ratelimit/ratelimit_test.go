package ratelimit

import (
	"sync"
	"testing"
)

func TestNew_MinimumOne(t *testing.T) {
	l := New(0)
	if !l.Acquire("k") {
		t.Fatal("expected Acquire to succeed on a limiter with effective max=1")
	}
	if l.Acquire("k") {
		t.Fatal("expected second Acquire to fail")
	}
	l.Release("k")
	if !l.Acquire("k") {
		t.Fatal("expected Acquire to succeed after Release")
	}
}

func TestAcquireRelease_Basic(t *testing.T) {
	l := New(2)

	if !l.Acquire("a") {
		t.Fatal("first Acquire should succeed")
	}
	if !l.Acquire("a") {
		t.Fatal("second Acquire should succeed (max=2)")
	}
	if l.Acquire("a") {
		t.Fatal("third Acquire should fail (max=2)")
	}

	l.Release("a")
	if !l.Acquire("a") {
		t.Fatal("Acquire should succeed after Release")
	}
}

func TestAcquireRelease_IndependentKeys(t *testing.T) {
	l := New(1)

	if !l.Acquire("x") {
		t.Fatal("Acquire(x) should succeed")
	}
	if !l.Acquire("y") {
		t.Fatal("Acquire(y) should succeed — independent key")
	}
	if l.Acquire("x") {
		t.Fatal("second Acquire(x) should fail")
	}

	l.Release("x")
	l.Release("y")
	if l.Count("x") != 0 {
		t.Fatalf("expected Count(x)=0, got %d", l.Count("x"))
	}
}

func TestRelease_UnknownKey(t *testing.T) {
	l := New(1)
	l.Release("nonexistent") // must not panic
}

func TestCount(t *testing.T) {
	l := New(5)
	if l.Count("z") != 0 {
		t.Fatal("Count on unseen key should be 0")
	}
	_ = l.Acquire("z")
	if l.Count("z") != 1 {
		t.Fatalf("expected Count=1, got %d", l.Count("z"))
	}
	l.Release("z")
	if l.Count("z") != 0 {
		t.Fatalf("expected Count=0 after Release, got %d", l.Count("z"))
	}
}

func TestConcurrentAcquire(t *testing.T) {
	const max = 3
	const goroutines = 50
	l := New(max)

	var (
		mu      sync.Mutex
		peak    int64
		current int64
		wg      sync.WaitGroup
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if l.Acquire("shared") {
				mu.Lock()
				current++
				if current > peak {
					peak = current
				}
				mu.Unlock()

				// Hold the slot briefly
				mu.Lock()
				current--
				mu.Unlock()
				l.Release("shared")
			}
		}()
	}
	wg.Wait()

	if peak > max {
		t.Fatalf("concurrency limit violated: peak=%d, max=%d", peak, max)
	}
	if l.Count("shared") != 0 {
		t.Fatalf("expected all slots released, Count=%d", l.Count("shared"))
	}
}
