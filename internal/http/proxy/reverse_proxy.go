package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/theroutercompany/api_router/internal/http/problem"
	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

// Options configure the reverse proxy.
type Options struct {
	Target  string
	Product string
}

// New constructs a reverse proxy handler for the given upstream.
func New(opts Options) (http.Handler, error) {
	target, err := url.Parse(opts.Target)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = 200 * time.Millisecond

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
