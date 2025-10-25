// Package proxy constructs reverse proxies with gateway-specific defaults such
// as TLS configuration, product headers, problem+json error handling, and
// HTTP/2-ready transports.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/theroutercompany/api_router/pkg/gateway/problem"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
	"golang.org/x/net/http2"
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

	h2cTransport := buildH2CTransport(target)
	proxy.Transport = &grpcAwareTransport{base: transport, h2c: h2cTransport}

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
		pkglog.Shared().Errorw("proxy upstream failure", "error", err, "url", r.URL.String())
		detail := fmt.Sprintf("Failed to reach %s service", opts.Product)
		problem.Write(w, http.StatusBadGateway, "Upstream Service Unavailable", detail, r.Header.Get("X-Trace-Id"), r.URL.Path)
	}

	return proxy, nil
}

func buildH2CTransport(target *url.URL) *http2.Transport {
	if target == nil || target.Scheme != "http" {
		return nil
	}

	return &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.Dial(network, addr)
		},
	}
}

type grpcAwareTransport struct {
	base *http.Transport
	h2c  *http2.Transport
}

func (t *grpcAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.shouldUseH2C(req) {
		h2cReq := cloneRequest(req)
		sanitizeH2CRequest(h2cReq)
		return t.h2c.RoundTrip(h2cReq)
	}
	return t.base.RoundTrip(req)
}

func (t *grpcAwareTransport) shouldUseH2C(req *http.Request) bool {
	if t.h2c == nil || req == nil || req.URL == nil {
		return false
	}
	if req.URL.Scheme != "http" {
		return false
	}
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/grpc")
}

func (t *grpcAwareTransport) CloseIdleConnections() {
	if t.base != nil {
		t.base.CloseIdleConnections()
	}
	if t.h2c != nil {
		t.h2c.CloseIdleConnections()
	}
}

func cloneRequest(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	clone := req.Clone(req.Context())
	clone.Body = req.Body
	clone.GetBody = req.GetBody
	clone.ContentLength = req.ContentLength
	clone.Host = req.Host
	clone.RequestURI = ""
	return clone
}

func sanitizeH2CRequest(req *http.Request) {
	if req == nil {
		return
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Upgrade", "Keep-Alive", "Transfer-Encoding"} {
		req.Header.Del(key)
	}
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
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
