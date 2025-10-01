package metrics

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestRegistryHandlerExposesMetrics(t *testing.T) {
    registry := NewRegistry()

    rr := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/metrics", nil)

    registry.Handler().ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", rr.Code)
    }

    if rr.Body.Len() == 0 {
        t.Fatalf("expected metrics body")
    }
}
