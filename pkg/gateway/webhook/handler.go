package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

const (
	defaultMaxBodyBytes int64 = 1 << 20 // 1 MiB
)

// Options configures the webhook handler behaviour.
type Options struct {
	Name            string
	Path            string
	TargetURL       string
	Secret          string
	SignatureHeader string
	MaxAttempts     int
	InitialBackoff  time.Duration
	Timeout         time.Duration
	Client          *http.Client
	Logger          pkglog.Logger
	MaxBodyBytes    int64
}

// New constructs an HTTP handler that validates webhook signatures and forwards payloads with retry/backoff.
func New(opts Options) (http.Handler, error) {
	if strings.TrimSpace(opts.Secret) == "" {
		return nil, errors.New("webhook secret required")
	}
	if strings.TrimSpace(opts.TargetURL) == "" {
		return nil, errors.New("webhook targetURL required")
	}
	if strings.TrimSpace(opts.SignatureHeader) == "" {
		return nil, errors.New("webhook signature header required")
	}
	if opts.MaxAttempts <= 0 {
		return nil, errors.New("webhook maxAttempts must be positive")
	}
	if opts.InitialBackoff <= 0 {
		return nil, errors.New("webhook initial backoff must be positive")
	}
	if opts.Timeout <= 0 {
		return nil, errors.New("webhook timeout must be positive")
	}
	if opts.Client == nil {
		opts.Client = &http.Client{
			Timeout: opts.Timeout,
		}
	}
	if opts.Logger == nil {
		opts.Logger = pkglog.Shared()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}

	handler := &webhookHandler{
		name:            opts.Name,
		targetURL:       opts.TargetURL,
		secret:          []byte(opts.Secret),
		signatureHeader: opts.SignatureHeader,
		maxAttempts:     opts.MaxAttempts,
		initialBackoff:  opts.InitialBackoff,
		timeout:         opts.Timeout,
		client:          opts.Client,
		logger:          opts.Logger,
		maxBodyBytes:    opts.MaxBodyBytes,
	}

	return handler, nil
}

type webhookHandler struct {
	name            string
	targetURL       string
	secret          []byte
	signatureHeader string
	maxAttempts     int
	initialBackoff  time.Duration
	timeout         time.Duration
	client          *http.Client
	logger          pkglog.Logger
	maxBodyBytes    int64
}

func (h *webhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	body, err := readRequestBody(r.Body, h.maxBodyBytes)
	if err != nil {
		var tooLarge *errBodyTooLarge
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.logger.Errorw("webhook read body failed", "error", err, "webhook", h.name)
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if err := h.verifySignature(r.Header.Get(h.signatureHeader), body); err != nil {
		h.logger.Warnw("webhook signature verification failed", "error", err, "webhook", h.name)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	if err := h.forwardWithRetry(r.Context(), r, body); err != nil {
		h.logger.Errorw("webhook delivery failed", "error", err, "webhook", h.name)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *webhookHandler) verifySignature(sigHeader string, body []byte) error {
	sig := strings.TrimSpace(sigHeader)
	if sig == "" {
		return errors.New("signature header missing")
	}
	if strings.HasPrefix(strings.ToLower(sig), "sha256=") {
		sig = sig[7:]
	}

	expectedMAC := computeHMAC(body, h.secret)
	provided, err := hex.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !hmac.Equal(expectedMAC, provided) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (h *webhookHandler) forwardWithRetry(parentCtx context.Context, original *http.Request, body []byte) error {
	backoff := h.initialBackoff
	for attempt := 1; attempt <= h.maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(parentCtx, h.timeout)
		err := h.forwardOnce(ctx, original, body, attempt)
		cancel()
		if err == nil {
			return nil
		}

		retryable := errors.Is(err, errUpstreamRetryable)
		h.logger.Warnw("webhook delivery attempt failed",
			"webhook", h.name,
			"attempt", attempt,
			"maxAttempts", h.maxAttempts,
			"retryable", retryable,
			"error", err,
		)

		if !retryable || attempt == h.maxAttempts {
			return err
		}

		select {
		case <-time.After(backoff):
			backoff = increaseBackoff(backoff, 4*time.Second)
		case <-parentCtx.Done():
			return parentCtx.Err()
		}
	}
	return errors.New("webhook delivery exhausted retries")
}

func (h *webhookHandler) forwardOnce(ctx context.Context, original *http.Request, body []byte, attempt int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	copyHeaders(original.Header, req.Header)
	req.Header.Set("X-Router-Webhook-Name", h.name)
	req.Header.Set("X-Router-Webhook-Attempt", fmt.Sprintf("%d", attempt))

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errUpstreamRetryable, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return fmt.Errorf("upstream returned status %d", resp.StatusCode)
	}
	return fmt.Errorf("%w: upstream status %d", errUpstreamRetryable, resp.StatusCode)
}

func readRequestBody(body io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBodyBytes
	}
	limited := io.LimitReader(body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &errBodyTooLarge{size: int64(len(data)), limit: maxBytes}
	}
	return data, nil
}

func computeHMAC(body []byte, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return mac.Sum(nil)
}

func copyHeaders(src http.Header, dst http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	dst.Del("Host")
}

func increaseBackoff(current time.Duration, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

var errUpstreamRetryable = errors.New("retryable upstream failure")

type errBodyTooLarge struct {
	size  int64
	limit int64
}

func (e *errBodyTooLarge) Error() string {
	return fmt.Sprintf("body size %d exceeds limit %d bytes", e.size, e.limit)
}
