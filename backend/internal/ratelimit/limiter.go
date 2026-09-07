// Package ratelimit provides an in-process token-bucket rate limiter keyed by
// an arbitrary string.
//
// The limiter is per-process, not distributed. Behind several API replicas the
// effective limit is therefore the configured rate multiplied by the number of
// replicas. That is a deliberate trade: it keeps the hot path free of a
// network round trip, and the limit exists to stop runaway CI loops rather
// than to meter billing. Moving to a shared store later means replacing this
// type, not its callers.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter tracks one token bucket per key.
type Limiter struct {
	mu      sync.RWMutex
	buckets map[string]*bucket

	// burst is how many requests may arrive at once before the configured
	// rate starts to apply.
	burst int
	// idleTTL is how long an unused bucket is kept before the janitor
	// reclaims it.
	idleTTL time.Duration

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// now is injectable so tests can control time.
	now func() time.Time
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	// rpm is remembered so that a changed limit rebuilds the bucket instead of
	// silently keeping the old rate.
	rpm int
}

// Config tunes a Limiter. The zero value is filled in with defaults.
type Config struct {
	// Burst is the number of requests allowed to arrive at once.
	Burst int
	// IdleTTL is how long an unused bucket is retained.
	IdleTTL time.Duration
	// SweepInterval is how often idle buckets are reclaimed.
	SweepInterval time.Duration
}

func (c Config) withDefaults() Config {
	if c.Burst <= 0 {
		c.Burst = 10
	}
	if c.IdleTTL <= 0 {
		c.IdleTTL = 10 * time.Minute
	}
	if c.SweepInterval <= 0 {
		c.SweepInterval = time.Minute
	}
	return c
}

// New builds a Limiter and starts its janitor. Call Close to stop it.
//
// The janitor matters: without it, every token that ever authenticates would
// leave a bucket behind, and the map would grow without bound for the life of
// the process.
func New(cfg Config) *Limiter {
	cfg = cfg.withDefaults()

	l := &Limiter{
		buckets: make(map[string]*bucket),
		burst:   cfg.Burst,
		idleTTL: cfg.IdleTTL,
		stop:    make(chan struct{}),
		now:     time.Now,
	}

	l.wg.Add(1)
	go l.sweep(cfg.SweepInterval)

	return l
}

// Allow reports whether a request for key may proceed under a limit of rpm
// requests per minute, consuming a token if so.
func (l *Limiter) Allow(key string, rpm int) bool {
	return l.bucketFor(key, rpm).Allow()
}

// Reserve returns how long the caller should wait before retrying, and whether
// the request is allowed now. It backs the Retry-After header, so a client
// gets told when to come back rather than having to guess.
func (l *Limiter) Reserve(key string, rpm int) (allowed bool, retryAfter time.Duration) {
	limiter := l.bucketFor(key, rpm)

	reservation := limiter.Reserve()
	if !reservation.OK() {
		// Only happens when the request could never be satisfied, which for a
		// burst of one token means immediately retryable.
		return false, time.Second
	}

	delay := reservation.Delay()
	if delay == 0 {
		return true, 0
	}

	// The request is not being served now, so give the token back rather than
	// making the caller wait for capacity it will not use.
	reservation.Cancel()
	return false, delay
}

// bucketFor returns the bucket for key, creating or rebuilding it as needed.
func (l *Limiter) bucketFor(key string, rpm int) *rate.Limiter {
	if rpm <= 0 {
		rpm = 60
	}

	now := l.now()

	// The common case is an existing bucket at an unchanged rate, so try under
	// a read lock first and only take the write lock when something changes.
	l.mu.RLock()
	existing, found := l.buckets[key]
	if found && existing.rpm == rpm {
		l.mu.RUnlock()

		l.mu.Lock()
		existing.lastSeen = now
		l.mu.Unlock()
		return existing.limiter
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Re-check: another goroutine may have created it between the two locks.
	if existing, found := l.buckets[key]; found && existing.rpm == rpm {
		existing.lastSeen = now
		return existing.limiter
	}

	created := &bucket{
		limiter:  rate.NewLimiter(rate.Limit(float64(rpm)/60.0), l.burst),
		lastSeen: now,
		rpm:      rpm,
	}
	l.buckets[key] = created
	return created.limiter
}

// sweep periodically discards buckets that have not been used recently.
func (l *Limiter) sweep(interval time.Duration) {
	defer l.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.reclaim()
		case <-l.stop:
			return
		}
	}
}

func (l *Limiter) reclaim() {
	cutoff := l.now().Add(-l.idleTTL)

	l.mu.Lock()
	defer l.mu.Unlock()

	for key, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// Len reports how many buckets are currently tracked.
func (l *Limiter) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.buckets)
}

// Close stops the janitor. It is idempotent.
func (l *Limiter) Close() {
	l.stopOnce.Do(func() { close(l.stop) })
	l.wg.Wait()
}
