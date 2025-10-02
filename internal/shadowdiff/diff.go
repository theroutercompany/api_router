package shadowdiff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Result captures the outcome of replaying a single fixture.
type Result struct {
	Fixture     Fixture
	NodeStatus  int
	GoStatus    int
	BodyDiff    string
	LatencyNode time.Duration
	LatencyGo   time.Duration
	Err         error
}

// Runner executes fixtures against Node and Go endpoints.
type Runner struct {
	Client      *http.Client
	Config      Config
	Normalizers []func([]byte) []byte
}

// Run executes all fixtures and returns their results.
func (r *Runner) Run(ctx context.Context, fixtures []Fixture) []Result {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	results := make([]Result, len(fixtures))
	sem := make(chan struct{}, r.Config.Concurrency)
	wg := sync.WaitGroup{}

	for i, fixture := range fixtures {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, fx Fixture) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = r.execute(ctx, client, fx)
		}(i, fixture)
	}

	wg.Wait()
	return results
}

func (r *Runner) execute(ctx context.Context, client *http.Client, fixture Fixture) Result {
	res := Result{Fixture: fixture}

	nodeResp, nodeLatency, nodeErr := r.send(ctx, client, r.Config.NodeBaseURL, fixture)
	goResp, goLatency, goErr := r.send(ctx, client, r.Config.GoBaseURL, fixture)

	res.LatencyNode = nodeLatency
	res.LatencyGo = goLatency

	if nodeErr != nil {
		res.Err = fmt.Errorf("node request failed: %w", nodeErr)
		return res
	}
	if goErr != nil {
		res.Err = fmt.Errorf("go request failed: %w", goErr)
		return res
	}

	res.NodeStatus = nodeResp.StatusCode
	res.GoStatus = goResp.StatusCode

	nodeBody, _ := io.ReadAll(nodeResp.Body)
	goBody, _ := io.ReadAll(goResp.Body)
	nodeResp.Body.Close()
	goResp.Body.Close()

	for _, normalizer := range r.Normalizers {
		nodeBody = normalizer(nodeBody)
		goBody = normalizer(goBody)
	}

	if !bytes.Equal(nodeBody, goBody) || res.NodeStatus != res.GoStatus {
		res.BodyDiff = diffJSON(nodeBody, goBody)
	}
	return res
}

func (r *Runner) send(ctx context.Context, client *http.Client, baseURL string, fixture Fixture) (*http.Response, time.Duration, error) {
	method := fixture.Method
	if method == "" {
		method = http.MethodGet
	}

	target, err := url.JoinPath(baseURL, fixture.Path)
	if err != nil {
		return nil, 0, fmt.Errorf("build url: %w", err)
	}

	reqBody := bytes.NewReader(fixture.Body)
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return nil, 0, err
	}

	for key, value := range fixture.Headers {
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return nil, latency, err
	}

	return resp, latency, nil
}

func diffJSON(expected, actual []byte) string {
	var expAny, actAny interface{}
	if err := json.Unmarshal(expected, &expAny); err != nil {
		if bytes.Equal(expected, actual) {
			return ""
		}
		return fmt.Sprintf("expected raw:\n%s\nactual:\n%s\n", expected, actual)
	}
	if err := json.Unmarshal(actual, &actAny); err != nil {
		if bytes.Equal(expected, actual) {
			return ""
		}
		return fmt.Sprintf("expected raw:\n%s\nactual:\n%s\n", expected, actual)
	}

	expCanonical, _ := json.MarshalIndent(expAny, "", "  ")
	actCanonical, _ := json.MarshalIndent(actAny, "", "  ")

	if bytes.Equal(expCanonical, actCanonical) {
		return ""
	}

	return fmt.Sprintf("expected:\n%s\nactual:\n%s\n", expCanonical, actCanonical)
}
