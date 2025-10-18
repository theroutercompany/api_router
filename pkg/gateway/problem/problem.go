// Package problem provides helpers for emitting RFC 7807 responses that
// include trace identifiers and consistent field casing across the gateway
// runtime and SDK embedding scenarios.
package problem

import (
	"encoding/json"
	"net/http"
)

// Response represents an RFC 7807 problem document.
type Response struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	TraceID  string `json:"traceId,omitempty"`
}

// Write emits a problem+json response.
func Write(w http.ResponseWriter, status int, title, detail, traceID, instance string) {
	resp := Response{
		Type:     "about:blank",
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: instance,
		TraceID:  traceID,
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
