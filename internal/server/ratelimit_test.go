package server

import (
	"sync"
	"testing"
	"time"
)

func TestAttemptLimiterEnforcesLimit(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{
		limit:  3,
		window: time.Hour,
		block:  time.Hour,
	})

	for i := 0; i < 3; i++ {
		if allowed, _ := limiter.Hit("key"); !allowed {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if allowed, retry := limiter.Check("key"); allowed || retry <= 0 {
		t.Fatalf("expected key to be blocked with a retry duration, got allowed=%v retry=%s", allowed, retry)
	}
	if allowed, _ := limiter.Hit("key"); allowed {
		t.Fatal("expected blocked key to reject new attempts")
	}

	limiter.Reset("key")
	if allowed, _ := limiter.Check("key"); !allowed {
		t.Fatal("expected reset to unblock the key")
	}
}

func TestAttemptLimiterCheckDoesNotRecord(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{limit: 1, window: time.Hour, block: time.Hour})
	for i := 0; i < 10; i++ {
		if allowed, _ := limiter.Check("key"); !allowed {
			t.Fatal("Check must not consume attempts")
		}
	}
	if allowed, _ := limiter.Hit("key"); !allowed {
		t.Fatal("first recorded attempt should be allowed")
	}
	if allowed, _ := limiter.Check("key"); allowed {
		t.Fatal("expected key to be blocked after one recorded attempt")
	}
}

func TestAttemptLimiterSeparatesKeys(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{limit: 1, window: time.Hour, block: time.Hour})
	if allowed, _ := limiter.Hit("one"); !allowed {
		t.Fatal("first key should be allowed")
	}
	if allowed, _ := limiter.Hit("two"); !allowed {
		t.Fatal("second key should be allowed independently")
	}
}

func TestAttemptLimiterBoundsEntries(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{
		limit:      2,
		window:     time.Hour,
		block:      time.Hour,
		maxEntries: 10,
	})

	for i := 0; i < 100; i++ {
		limiter.Hit(string(rune('a' + i%26)))
	}

	limiter.mu.Lock()
	count := len(limiter.entries)
	limiter.mu.Unlock()
	if count > 10 {
		t.Fatalf("expected at most 10 entries, got %d", count)
	}
}

func TestAttemptLimiterConcurrentAccess(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{limit: 50, window: time.Minute, block: time.Minute})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key"
			if i%2 == 0 {
				limiter.Hit(key)
			} else {
				limiter.Check(key)
			}
		}(i)
	}
	wg.Wait()
}

func TestAttemptLimiterPrunesExpiredBlockedEntries(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{limit: 1, window: time.Hour, block: time.Hour})
	now := time.Now()

	limiter.mu.Lock()
	limiter.entries[hashLimiterKey("expired")] = &limiterEntry{
		blockedUntil: now.Add(-time.Minute),
	}
	limiter.entries[hashLimiterKey("active")] = &limiterEntry{
		blockedUntil: now.Add(time.Minute),
	}
	limiter.pruneAllLocked(now)
	_, expiredExists := limiter.entries[hashLimiterKey("expired")]
	_, activeExists := limiter.entries[hashLimiterKey("active")]
	limiter.mu.Unlock()

	if expiredExists {
		t.Fatal("expected expired blocked entry to be pruned")
	}
	if !activeExists {
		t.Fatal("expected active blocked entry to be retained")
	}
}

func TestAttemptLimiterBlockExpires(t *testing.T) {
	limiter := newAttemptLimiter(limiterConfig{
		limit:  1,
		window: 20 * time.Millisecond,
		block:  20 * time.Millisecond,
	})
	if allowed, _ := limiter.Hit("key"); !allowed {
		t.Fatal("first attempt should be allowed")
	}
	if allowed, _ := limiter.Check("key"); allowed {
		t.Fatal("expected key to be blocked")
	}
	time.Sleep(30 * time.Millisecond)
	if allowed, _ := limiter.Check("key"); !allowed {
		t.Fatal("expected block to expire")
	}
}
