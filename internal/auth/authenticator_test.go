package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/theroutercompany/api_router/internal/config"
)

func TestAuthenticateSuccess(t *testing.T) {
	cfg := config.AuthConfig{Secret: "secret", Audiences: []string{"api"}, Issuer: "gateway"}
	authenticator, err := New(cfg)
	if err != nil {
		t.Fatalf("expected authenticator, got error: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "user-123",
		Audience:  jwt.ClaimStrings{"api"},
		Issuer:    "gateway",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	})

	tokenString, err := token.SignedString([]byte(cfg.Secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	principal, err := authenticator.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal.Subject != "user-123" {
		t.Fatalf("unexpected subject: %s", principal.Subject)
	}
}

func TestAuthenticateMissingHeader(t *testing.T) {
	authenticator, _ := New(config.AuthConfig{Secret: "secret"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if _, err := authenticator.Authenticate(req); err == nil {
		t.Fatalf("expected error when header missing")
	}
}
