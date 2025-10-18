package testdata

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// NewSSEServer returns an http.Handler that emits Server-Sent Events.
func NewSSEServer() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		type payload struct {
			ID   int    `json:"id"`
			Hint string `json:"hint"`
		}

		sent := 0
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				sent++
				message := payload{ID: sent, Hint: fmt.Sprintf("seed-%d", rand.Intn(100))}
				data, _ := json.Marshal(message)
				fmt.Fprintf(w, "id: %d\nevent: tick\ndata: %s\n\n", sent, data)
				flusher.Flush()
				if sent >= 5 {
					return
				}
			}
		}
	})
}
