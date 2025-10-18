package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimiter struct {
	mu          sync.Mutex
	window      time.Duration
	max         int
	limit       rate.Limit
	clients     map[string]*clientLimiter
	nextCleanup time.Time
}

func newRateLimiter(window time.Duration, max int) *rateLimiter {
	if window <= 0 || max <= 0 {
		return &rateLimiter{
			window: 0,
			max:    0,
		}
	}

	seconds := window.Seconds()
	if seconds <= 0 {
		seconds = 1
	}

	limit := rate.Limit(float64(max) / seconds)
	if limit <= 0 {
		limit = rate.Every(window / time.Duration(max))
	}

	return &rateLimiter{
		window:  window,
		max:     max,
		limit:   limit,
		clients: make(map[string]*clientLimiter),
	}
}

func (r *rateLimiter) allow(key string, now time.Time) bool {
	if r == nil || r.window <= 0 || r.max <= 0 {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.clients == nil {
		r.clients = make(map[string]*clientLimiter)
	}

	client, ok := r.clients[key]
	if !ok {
		client = &clientLimiter{
			limiter:  rate.NewLimiter(r.limit, r.max),
			lastSeen: now,
		}
		r.clients[key] = client
	} else {
		client.lastSeen = now
	}

	allowed := client.limiter.Allow()

	if r.nextCleanup.IsZero() || now.After(r.nextCleanup) {
		r.cleanupLocked(now)
		r.nextCleanup = now.Add(r.window)
	}

	return allowed
}

func (r *rateLimiter) cleanupLocked(now time.Time) {
	if r.clients == nil {
		return
	}

	threshold := now.Add(-2 * r.window)
	for key, client := range r.clients {
		if client.lastSeen.Before(threshold) {
			delete(r.clients, key)
		}
	}
}
