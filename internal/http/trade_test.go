package gatewayhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/theroutercompany/api_router/internal/auth"
	"github.com/theroutercompany/api_router/internal/config"
)

func TestProtectedHandlerRequiresAuth(t *testing.T) {
	authenticator := newTestAuthenticator(t, []string{})
	s := &Server{authenticator: authenticator}
	handler := s.buildProtectedHandler("trade", []string{"trade.read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/v1/trade/orders", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["title"] != "Authentication Required" {
		t.Fatalf("unexpected title: %v", body["title"])
	}
}

func TestProtectedHandlerEnforcesScopes(t *testing.T) {
	authenticator := newTestAuthenticator(t, []string{"api"})
	s := &Server{authenticator: authenticator}
	handler := s.buildProtectedHandler("trade", []string{"trade.read", "trade.write"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	token := newBearerToken(t, authenticator, "user", []string{"api"}, []string{"finance.read"})

	req := httptest.NewRequest(http.MethodGet, "/v1/trade/orders", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestProtectedHandlerProxiesOnSuccess(t *testing.T) {
	authenticator := newTestAuthenticator(t, []string{"api"})
	s := &Server{authenticator: authenticator}

	proxied := false
	handler := s.buildProtectedHandler("trade", []string{"trade.read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		if r.Header.Get("X-Router-Product") != "trade" {
			t.Errorf("expected X-Router-Product header")
		}
		w.WriteHeader(http.StatusOK)
	}))

	token := newBearerToken(t, authenticator, "user", []string{"api"}, []string{"trade.read"})

	req := httptest.NewRequest(http.MethodGet, "/v1/trade/orders", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !proxied {
		t.Fatalf("expected proxy to be invoked")
	}
}

func TestTaskHandlerUsesTaskProduct(t *testing.T) {
	authenticator := newTestAuthenticator(t, nil)
	s := &Server{authenticator: authenticator}

	proxied := false
	handler := s.buildProtectedHandler("task", []string{"task.read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		if r.Header.Get("X-Router-Product") != "task" {
			t.Errorf("expected task product header, got %s", r.Header.Get("X-Router-Product"))
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	token := newBearerToken(t, authenticator, "user", nil, []string{"task.read"})
	req := httptest.NewRequest(http.MethodGet, "/v1/task/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	if !proxied {
		t.Fatalf("expected proxy to be invoked")
	}
}

func newTestAuthenticator(t *testing.T, audiences []string) *auth.Authenticator {
	t.Helper()
	authenticator, err := auth.New(config.AuthConfig{
		Secret:    "secret",
		Audiences: audiences,
		Issuer:    "gateway",
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return authenticator
}

func newBearerToken(t *testing.T, authenticator *auth.Authenticator, subject string, audiences, scopes []string) string {
	t.Helper()

	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Audience:  audiences,
		Issuer:    "gateway",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, struct {
		jwt.RegisteredClaims
		Scp []string `json:"scp"`
	}{
		RegisteredClaims: claims,
		Scp:              scopes,
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tokenString
}
