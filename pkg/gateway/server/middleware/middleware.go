package middleware

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/cors"
)

// Logger represents the subset of logging behaviour required by the gateway middleware.
type Logger interface {
	Infow(msg string, keysAndValues ...any)
	Warnw(msg string, keysAndValues ...any)
	Errorw(msg string, keysAndValues ...any)
}

// ProblemWriter emits problem+json responses.
type ProblemWriter func(w http.ResponseWriter, status int, title, detail, traceID, instance string)

// EnsureIDs enriches the request with request/trace IDs.
type EnsureIDs func(*http.Request) (*http.Request, string, string)

// TraceIDFromContext extracts the trace ID from the request context.
type TraceIDFromContext func(context.Context) string

// RequestIDFromContext extracts the request ID from the request context.
type RequestIDFromContext func(context.Context) string

// ClientAddress resolves the caller's IP from the request.
type ClientAddress func(*http.Request) string

// TrackFunc captures protocol metrics for a completed request.
type TrackFunc func(*http.Request) func(status int, elapsed time.Duration)

// HijackedFunc captures protocol metrics for upgraded connections and optionally wraps the net.Conn.
type HijackedFunc func(*http.Request) (func(), func(net.Conn) net.Conn)

// AllowFunc determines whether a client is permitted to proceed based on a key and timestamp.
type AllowFunc func(key string, now time.Time) bool

// ClientKey derives the rate-limit key for a request.
type ClientKey func(*http.Request) string

// RequestMetadata ensures every request has IDs and the response echoes them back.
func RequestMetadata(ensure EnsureIDs) func(http.Handler) http.Handler {
	if ensure == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		if next == nil {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, requestID, traceID := ensure(r)
			w.Header().Set("X-Request-Id", requestID)
			if traceID != "" {
				w.Header().Set("X-Trace-Id", traceID)
			}
			next.ServeHTTP(w, req)
		})
	}
}

// SecurityHeaders applies standard hardening headers.
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if next == nil {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headers := w.Header()
			headers.Set("X-Content-Type-Options", "nosniff")
			headers.Set("X-Frame-Options", "DENY")
			headers.Set("Referrer-Policy", "no-referrer")
			headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimit rejects requests exceeding the configured limit and caps readable bytes.
func BodyLimit(limit int64, trace TraceIDFromContext, write ProblemWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if next == nil {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				tid := ""
				if trace != nil {
					tid = trace(r.Context())
				}
				if write != nil {
					write(w, http.StatusRequestEntityTooLarge, "Payload Too Large", fmt.Sprintf("Request body exceeds %d bytes", limit), tid, r.URL.Path)
					return
				}
				http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit enforces per-client rate limiting using the supplied allow/key functions.
func RateLimit(allow AllowFunc, key ClientKey, now func() time.Time, trace TraceIDFromContext, write ProblemWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if next == nil || allow == nil || key == nil || now == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			client := key(r)
			if allow(client, now()) {
				next.ServeHTTP(w, r)
				return
			}
			if write != nil {
				tid := ""
				if trace != nil {
					tid = trace(r.Context())
				}
				write(w, http.StatusTooManyRequests, "Too Many Requests", "Rate limit exceeded", tid, r.URL.Path)
			} else {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			}
		})
	}
}

// CORS applies the configured cors handler and rejects disallowed origins with a problem response.
func CORS(handler *cors.Cors, trace TraceIDFromContext, write ProblemWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if handler == nil || next == nil {
			return next
		}
		corsHandler := handler.Handler(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin != "" && !handler.OriginAllowed(r) {
				if write != nil {
					tid := ""
					if trace != nil {
						tid = trace(r.Context())
					}
					write(w, http.StatusForbidden, "Not allowed by CORS", fmt.Sprintf("Origin %s is not allowed", origin), tid, r.URL.Path)
				} else {
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				}
				return
			}
			corsHandler.ServeHTTP(w, r)
		})
	}
}

// Logging records structured request information and integrates protocol metrics tracking.
func Logging(
	logger Logger,
	track TrackFunc,
	hijacked HijackedFunc,
	requestID RequestIDFromContext,
	traceID TraceIDFromContext,
	clientAddr ClientAddress,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if next == nil || logger == nil {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			trackFn := func(int, time.Duration) {}
			if track != nil {
				if fn := track(r); fn != nil {
					trackFn = fn
				}
			}

			var hijackTracker func() (func(), func(net.Conn) net.Conn)
			if hijacked != nil {
				hijackTracker = func() (func(), func(net.Conn) net.Conn) {
					return hijacked(r)
				}
			}

			writer := newLoggingResponseWriter(w, hijackTracker)
			next.ServeHTTP(writer, r)

			duration := time.Since(start)
			status := writer.status
			if status == 0 {
				status = http.StatusOK
			}

			trackFn(status, duration)

			fields := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
				"durationMs", float64(duration.Microseconds()) / 1000.0,
				"bytesWritten", writer.bytes,
			}

			if requestID != nil {
				if rid := requestID(r.Context()); rid != "" {
					fields = append(fields, "requestId", rid)
				}
			}
			if traceID != nil {
				if tid := traceID(r.Context()); tid != "" {
					fields = append(fields, "traceId", tid)
				}
			}
			if clientAddr != nil {
				if remote := clientAddr(r); remote != "" {
					fields = append(fields, "remoteAddr", remote)
				}
			}

			switch {
			case status >= 500:
				logger.Errorw("http request completed", fields...)
			case status >= 400:
				logger.Warnw("http request completed", fields...)
			default:
				logger.Infow("http request completed", fields...)
			}
		})
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status        int
	bytes         int
	hijackTracker func() (func(), func(net.Conn) net.Conn)
	hijackOnce    sync.Once
}

func newLoggingResponseWriter(w http.ResponseWriter, tracker func() (func(), func(net.Conn) net.Conn)) *loggingResponseWriter {
	return &loggingResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		hijackTracker:  tracker,
	}
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *loggingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}

	if w.hijackTracker != nil {
		var closer func()
		var wrapper func(net.Conn) net.Conn
		w.hijackOnce.Do(func() {
			closer, wrapper = w.hijackTracker()
		})
		if wrapper != nil {
			conn = wrapper(conn)
		}
		if closer != nil {
			conn = &trackingConn{Conn: conn, onClose: closer}
		}
	}

	return conn, rw, nil
}

func (w *loggingResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

type trackingConn struct {
	net.Conn
	onClose func()
	once    sync.Once
	timeout time.Duration
}

func (c *trackingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *trackingConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *trackingConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}
