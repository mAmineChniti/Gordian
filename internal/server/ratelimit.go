package server

import (
	"crypto/sha256"
	"sync"
	"time"
)

type limiterConfig struct {
	limit      int
	window     time.Duration
	block      time.Duration
	maxEntries int
}

type limiterEntry struct {
	hits         []time.Time
	blockedUntil time.Time
}

type limiterKey [sha256.Size]byte

type attemptLimiter struct {
	mu          sync.Mutex
	cfg         limiterConfig
	entries     map[limiterKey]*limiterEntry
	lastCleanup time.Time
}

func newAttemptLimiter(cfg limiterConfig) *attemptLimiter {
	if cfg.maxEntries <= 0 {
		cfg.maxEntries = 100_000
	}
	return &attemptLimiter{
		cfg:         cfg,
		entries:     make(map[limiterKey]*limiterEntry),
		lastCleanup: time.Now(),
	}
}

// Check reports whether a key is currently blocked without recording a hit.
func (l *attemptLimiter) Check(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.cleanupLocked(now)
	return l.checkLocked(hashLimiterKey(key), now)
}

// Hit records an attempt and reports whether it is allowed. The configured
// limit allows exactly `limit` attempts per window before blocking.
func (l *attemptLimiter) Hit(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.cleanupLocked(now)

	bucket := hashLimiterKey(key)
	if allowed, retry := l.checkLocked(bucket, now); !allowed {
		return false, retry
	}

	entry := l.entryLocked(bucket)
	if entry == nil {
		// Fail closed when the bounded map cannot admit another key.
		return false, l.cfg.window
	}

	entry.hits = append(entry.hits, now)
	if len(entry.hits) >= l.cfg.limit {
		entry.blockedUntil = now.Add(l.cfg.block)
		entry.hits = nil
	}

	return true, 0
}

// Fail records a failed authentication attempt.
func (l *attemptLimiter) Fail(key string) (bool, time.Duration) {
	return l.Hit(key)
}

func (l *attemptLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, hashLimiterKey(key))
}

func (l *attemptLimiter) checkLocked(bucket limiterKey, now time.Time) (bool, time.Duration) {
	entry, ok := l.entries[bucket]
	if !ok {
		return true, 0
	}

	if now.Before(entry.blockedUntil) {
		return false, entry.blockedUntil.Sub(now)
	}
	if !entry.blockedUntil.IsZero() {
		entry.blockedUntil = time.Time{}
		entry.hits = nil
	}

	entry.hits = pruneHits(entry.hits, now.Add(-l.cfg.window))
	if len(entry.hits) >= l.cfg.limit {
		return false, entry.hits[0].Add(l.cfg.window).Sub(now)
	}
	return true, 0
}

func (l *attemptLimiter) entryLocked(bucket limiterKey) *limiterEntry {
	if entry, ok := l.entries[bucket]; ok {
		return entry
	}
	if len(l.entries) >= l.cfg.maxEntries {
		l.pruneAllLocked(time.Now())
		if len(l.entries) >= l.cfg.maxEntries {
			return nil
		}
	}
	entry := &limiterEntry{}
	l.entries[bucket] = entry
	return entry
}

func (l *attemptLimiter) cleanupLocked(now time.Time) {
	if now.Sub(l.lastCleanup) < 5*time.Minute && len(l.entries) < l.cfg.maxEntries {
		return
	}
	l.lastCleanup = now
	l.pruneAllLocked(now)
}

func (l *attemptLimiter) pruneAllLocked(now time.Time) {
	cutoff := now.Add(-l.cfg.window)
	for key, entry := range l.entries {
		if now.Before(entry.blockedUntil) {
			continue
		}
		// Clear expired blocks so entries can be pruned instead of lingering
		// forever and eventually exhausting the bounded key space.
		entry.blockedUntil = time.Time{}
		entry.hits = pruneHits(entry.hits, cutoff)
		if len(entry.hits) == 0 {
			delete(l.entries, key)
		}
	}
}

func pruneHits(hits []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(hits) && hits[first].Before(cutoff) {
		first++
	}
	if first == 0 {
		return hits
	}
	return append(hits[:0], hits[first:]...)
}

func hashLimiterKey(key string) limiterKey {
	return sha256.Sum256([]byte(key))
}
