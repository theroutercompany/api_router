package health

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Upstream identifies a dependency to probe for readiness.
type Upstream struct {
	Name       string
	BaseURL    string
	HealthPath string
}

// UpstreamReport captures the outcome of probing a single upstream.
type UpstreamReport struct {
	Name       string    `json:"name"`
	Healthy    bool      `json:"healthy"`
	StatusCode int       `json:"statusCode,omitempty"`
	Error      string    `json:"error,omitempty"`
	CheckedAt  time.Time `json:"checkedAt"`
}

// Report aggregates readiness across upstreams.
type Report struct {
	Status    string           `json:"status"`
	CheckedAt time.Time        `json:"checkedAt"`
	Upstreams []UpstreamReport `json:"upstreams"`
}

// Checker evaluates health of upstream dependencies.
type Checker struct {
	client    *http.Client
	upstreams []Upstream
	timeout   time.Duration
	userAgent string
}

// NewChecker returns a checker configured with the given dependencies.
func NewChecker(client *http.Client, upstreams []Upstream, timeout time.Duration, userAgent string) *Checker {
	if client == nil {
		client = http.DefaultClient
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if userAgent == "" {
		userAgent = "api-router-gateway/readyz"
	}

	return &Checker{
		client:    client,
		upstreams: upstreams,
		timeout:   timeout,
		userAgent: userAgent,
	}
}

// Readiness probes configured upstreams and returns an aggregated report.
func (c *Checker) Readiness(ctx context.Context) Report {
	if len(c.upstreams) == 0 {
		return Report{Status: "ready", CheckedAt: time.Now().UTC()}
	}

	results := make([]UpstreamReport, len(c.upstreams))
	var wg sync.WaitGroup

	for idx, upstream := range c.upstreams {
		wg.Add(1)
		go func(i int, u Upstream) {
			defer wg.Done()
			results[i] = c.probe(ctx, u)
		}(idx, upstream)
	}

	wg.Wait()

	report := Report{
		CheckedAt: time.Now().UTC(),
		Upstreams: results,
	}

	report.Status = "ready"
	for _, r := range results {
		if !r.Healthy {
			report.Status = "degraded"
			break
		}
	}

	return report
}

func (c *Checker) probe(ctx context.Context, upstream Upstream) UpstreamReport {
	checkedAt := time.Now().UTC()
	report := UpstreamReport{
		Name:      upstream.Name,
		Healthy:   false,
		CheckedAt: checkedAt,
	}

	targetURL, err := url.JoinPath(upstream.BaseURL, upstream.HealthPath)
	if err != nil {
		report.Error = fmt.Sprintf("failed to build upstream url: %v", err)
		return report
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		report.Error = fmt.Sprintf("failed to create request: %v", err)
		return report
	}

	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		select {
		case <-reqCtx.Done():
			report.Error = reqCtx.Err().Error()
		default:
			report.Error = err.Error()
		}
		return report
	}
	defer resp.Body.Close()

	report.StatusCode = resp.StatusCode
	report.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !report.Healthy {
		report.Error = fmt.Sprintf("health check failed with status %d", resp.StatusCode)
	}

	return report
}
