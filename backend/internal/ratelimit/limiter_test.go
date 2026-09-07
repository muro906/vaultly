package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestAllowPermitsBurstThenLimits(t *testing.T) {
	l := New(Config{Burst: 5})
	defer l.Close()

	// The burst is spendable immediately.
	for i := 0; i < 5; i++ {
		if !l.Allow("token-a", 60) {
			t.Fatalf("request %d within the burst was denied", i+1)
		}
	}
	// The next one has to wait for the bucket to refill.
	if l.Allow("token-a", 60) {
		t.Fatal("request beyond the burst was allowed")
	}
}

func TestLimitsAreIndependentPerKey(t *testing.T) {
	l := New(Config{Burst: 2})
	defer l.Close()

	for i := 0; i < 2; i++ {
		l.Allow("token-a", 60)
	}
	if l.Allow("token-a", 60) {
		t.Fatal("token-a should be exhausted")
	}

	// One noisy token must not throttle everyone else.
	if !l.Allow("token-b", 60) {
		t.Fatal("token-b was denied because token-a was exhausted")
	}
}

func TestReserveReportsRetryAfter(t *testing.T) {
	l := New(Config{Burst: 1})
	defer l.Close()

	allowed, retryAfter := l.Reserve("token", 60)
	if !allowed {
		t.Fatal("first request was denied")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %s on an allowed request, want 0", retryAfter)
	}

	allowed, retryAfter = l.Reserve("token", 60)
	if allowed {
		t.Fatal("second request was allowed despite a burst of 1")
	}
	// At 60/minute a token refills every second, so the wait should be close
	// to that and never zero.
	if retryAfter <= 0 || retryAfter > 2*time.Second {
		t.Errorf("retryAfter = %s, want a positive value under 2s", retryAfter)
	}
}

func TestReserveDoesNotConsumeWhenDenied(t *testing.T) {
	l := New(Config{Burst: 1})
	defer l.Close()

	l.Reserve("token", 60)

	// A denied reservation must return its token, otherwise repeated polling
	// would push the retry time further and further out.
	_, first := l.Reserve("token", 60)
	_, second := l.Reserve("token", 60)

	if second > first+50*time.Millisecond {
		t.Errorf("retry delay grew from %s to %s across denied reservations", first, second)
	}
}

func TestBucketIsRebuiltWhenRateChanges(t *testing.T) {
	l := New(Config{Burst: 2})
	defer l.Close()

	for i := 0; i < 2; i++ {
		l.Allow("token", 60)
	}
	if l.Allow("token", 60) {
		t.Fatal("token should be exhausted at 60 rpm")
	}

	// Raising a token's limit should take effect rather than being masked by
	// the bucket built under the old rate.
	if !l.Allow("token", 6000) {
		t.Fatal("request was denied after the rate limit was raised")
	}
	if l.Len() != 1 {
		t.Errorf("bucket count = %d, want 1 after a rate change", l.Len())
	}
}

func TestJanitorReclaimsIdleBuckets(t *testing.T) {
	l := New(Config{Burst: 1, IdleTTL: time.Minute, SweepInterval: time.Hour})
	defer l.Close()

	l.Allow("token-a", 60)
	l.Allow("token-b", 60)
	if l.Len() != 2 {
		t.Fatalf("bucket count = %d, want 2", l.Len())
	}

	// Jump past the idle TTL and reclaim directly rather than waiting on the
	// janitor's ticker.
	l.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	l.reclaim()

	if l.Len() != 0 {
		t.Errorf("bucket count = %d after reclaim, want 0", l.Len())
	}
}

func TestActiveBucketsSurviveReclaim(t *testing.T) {
	l := New(Config{Burst: 5, IdleTTL: time.Minute, SweepInterval: time.Hour})
	defer l.Close()

	l.Allow("old", 60)

	// Move time forward, then touch one key so only the untouched one is idle.
	l.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	l.Allow("fresh", 60)
	l.reclaim()

	if l.Len() != 1 {
		t.Fatalf("bucket count = %d, want 1", l.Len())
	}
	if _, found := l.buckets["fresh"]; !found {
		t.Error("the recently used bucket was reclaimed")
	}
}

func TestZeroRPMFallsBackToADefault(t *testing.T) {
	l := New(Config{Burst: 1})
	defer l.Close()

	// A misconfigured zero must not mean "deny everything" or divide by zero.
	if !l.Allow("token", 0) {
		t.Error("a zero rate limit denied the first request")
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	l := New(Config{Burst: 1000})
	defer l.Close()

	const goroutines = 50
	const perGoroutine = 100

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				// Deliberately overlapping keys, so goroutines contend for the
				// same buckets as well as creating new ones.
				l.Allow(string(rune('a'+i%5)), 6000)
				l.Reserve(string(rune('a'+j%5)), 6000)
			}
		}(i)
	}
	wg.Wait()

	if l.Len() != 5 {
		t.Errorf("bucket count = %d, want 5", l.Len())
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	l := New(Config{})
	l.Close()
	l.Close() // must not panic on a second close
}
