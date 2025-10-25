package server

import "testing"

func TestWebsocketLimiterAcquireRelease(t *testing.T) {
	limiter := newWebsocketLimiter(2)

	release1, ok := limiter.Acquire()
	if !ok || release1 == nil {
		t.Fatalf("expected acquire success")
	}
	release2, ok := limiter.Acquire()
	if !ok || release2 == nil {
		t.Fatalf("expected second acquire success")
	}
	if _, ok := limiter.Acquire(); ok {
		t.Fatalf("expected acquire to fail when limit reached")
	}
	release1()
	if release1 == nil {
		t.Fatalf("release should not be nil")
	}
	if _, ok := limiter.Acquire(); !ok {
		t.Fatalf("expected acquire to succeed after release")
	}
}

func TestWebsocketLimiterUnlimited(t *testing.T) {
	limiter := newWebsocketLimiter(0)
	var releases []func()
	for i := 0; i < 5; i++ {
		release, ok := limiter.Acquire()
		if !ok || release == nil {
			t.Fatalf("expected unlimited limiter to succeed")
		}
		releases = append(releases, release)
	}
	for _, rel := range releases {
		rel()
	}
}
