package gatewayhttp

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type contextKey string

const (
	requestIDKey contextKey = "requestID"
	traceIDKey   contextKey = "traceID"
)

func ensureRequestIDs(r *http.Request) (*http.Request, string, string) {
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.NewString()
		r.Header.Set("X-Request-Id", requestID)
	}

	traceID := r.Header.Get("X-Trace-Id")
	if traceID == "" {
		traceID = requestID
		r.Header.Set("X-Trace-Id", traceID)
	}

	ctx := context.WithValue(r.Context(), requestIDKey, requestID)
	ctx = context.WithValue(ctx, traceIDKey, traceID)

	return r.WithContext(ctx), requestID, traceID
}
