// Package proxy constructs reverse proxies with gateway-specific defaults such
// as TLS configuration, product headers, problem+json error handling, and
// HTTP/2-ready transports.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/theroutercompany/api_router/pkg/gateway/problem"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

// TLSConfig represents TLS settings applied to upstream requests.
type TLSConfig struct {
	Enabled            bool
	InsecureSkipVerify bool
	CAFile             string
	ClientCertFile     string
	ClientKeyFile      string
}

// Options configure the reverse proxy.
type Options struct {
	Target  string
	Product string
	TLS     TLSConfig
}

// New constructs a reverse proxy handler for the given upstream.
func New(opts Options) (http.Handler, error) {
	target, err := url.Parse(opts.Target)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = 200 * time.Millisecond

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 10,
	}

	if opts.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(opts.TLS)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	}

	proxy.Transport = transport

	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		r.Host = target.Host

		if opts.Product != "" {
			r.Header.Set("X-Router-Product", opts.Product)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		pkglog.Logger().Errorw("proxy upstream failure", "error", err, "url", r.URL.String())
		detail := fmt.Sprintf("Failed to reach %s service", opts.Product)
		problem.Write(w, http.StatusBadGateway, "Upstream Service Unavailable", detail, r.Header.Get("X-Trace-Id"), r.URL.Path)
	}

	return proxy, nil
}

func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse CA bundle %q: %w", cfg.CAFile, errInvalidPEM)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertFile != "" || cfg.ClientKeyFile != "" {
		if cfg.ClientCertFile == "" || cfg.ClientKeyFile == "" {
			return nil, errors.New("client certificate and key must both be provided")
		}

		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

var errInvalidPEM = errors.New("invalid PEM block")
