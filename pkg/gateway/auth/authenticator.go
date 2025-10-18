// Package auth exposes reusable authentication primitives for gateway runtimes.
//
// It currently exports a JWT-based authenticator that enforces audience/issuer
// checks and scope validation, mirroring the legacy gateway behaviour while
// remaining embeddable from downstream services.
package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
)

// Principal represents the authenticated caller.
type Principal struct {
	Subject string
	Scopes  []string
	Token   string
}

// Error categorises authentication failures.
type Error struct {
	Status int
	Title  string
	Detail string
}

func (e Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Title
}

var (
	errMissingAuthorization = Error{Status: http.StatusUnauthorized, Title: "Authentication Required", Detail: "Missing authorization header"}
	errMalformedHeader      = Error{Status: http.StatusUnauthorized, Title: "Authentication Required", Detail: "Malformed authorization header"}
	errTokenInvalid         = Error{Status: http.StatusUnauthorized, Title: "Authentication Required", Detail: "Invalid or expired token"}
)

// Authenticator validates JWT bearer tokens.
type Authenticator struct {
	secret    []byte
	audiences []string
	issuer    string
}

// New constructs an authenticator from configuration.
func New(cfg gatewayconfig.AuthConfig) (*Authenticator, error) {
	if cfg.Secret == "" {
		return nil, errors.New("jwt secret not configured")
	}

	return &Authenticator{
		secret:    []byte(cfg.Secret),
		audiences: cfg.Audiences,
		issuer:    cfg.Issuer,
	}, nil
}

// Authenticate validates the request's bearer token.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errMissingAuthorization
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errMalformedHeader
	}

	tokenString := strings.TrimSpace(parts[1])
	if tokenString == "" {
		return nil, errMalformedHeader
	}

	principal, err := a.parseToken(tokenString)
	if err != nil {
		var authErr Error
		if errors.As(err, &authErr) {
			return nil, authErr
		}
		return nil, errTokenInvalid
	}

	principal.Token = tokenString
	return principal, nil
}

func (a *Authenticator) parseToken(tokenString string) (*Principal, error) {
	options := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})}
	if len(a.audiences) > 0 {
		options = append(options, jwt.WithAudience(a.audiences...))
	}
	if a.issuer != "" {
		options = append(options, jwt.WithIssuer(a.issuer))
	}

	parser := jwt.NewParser(options...)
	claims := &gatewayClaims{}

	token, err := parser.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (interface{}, error) {
		return a.secret, nil
	})
	if err != nil {
		return nil, Error{Status: http.StatusUnauthorized, Title: "Authentication Required", Detail: err.Error()}
	}

	if !token.Valid {
		return nil, errTokenInvalid
	}

	principal := &Principal{
		Subject: claims.Subject,
		Scopes:  claims.Scopes(),
	}
	return principal, nil
}

func (p *Principal) HasAnyScope(required []string) bool {
	for _, scope := range required {
		for _, owned := range p.Scopes {
			if scope == owned {
				return true
			}
		}
	}
	return false
}

type gatewayClaims struct {
	Scope string   `json:"scope"`
	Scp   []string `json:"scp"`
	jwt.RegisteredClaims
}

func (c *gatewayClaims) Scopes() []string {
	if len(c.Scp) > 0 {
		return c.Scp
	}
	if c.Scope == "" {
		return nil
	}
	parts := strings.Fields(c.Scope)
	return parts
}
