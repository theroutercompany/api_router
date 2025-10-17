package testdata

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// GraphQLStreamHandler emits chunked JSON responses to simulate GraphQL subscriptions/@defer streams.
type GraphQLStreamHandler struct {
	onCancel sync.Once
	cancelCh chan struct{}
}

func NewGraphQLStreamHandler() *GraphQLStreamHandler {
	return &GraphQLStreamHandler{cancelCh: make(chan struct{})}
}

func (h *GraphQLStreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()

	type payload struct {
		Data map[string]any `json:"data"`
	}

	index := 0
	for {
		select {
		case <-r.Context().Done():
			h.onCancel.Do(func() { close(h.cancelCh) })
			return
		case <-ticker.C:
			index++
			body := payload{Data: map[string]any{"message": index}}
			data, _ := json.Marshal(body)
			w.Write(data)
			w.Write([]byte("\n"))
			flusher.Flush()
		}
	}
}

// Cancelled returns a channel that is closed when the client context is cancelled.
func (h *GraphQLStreamHandler) Cancelled() <-chan struct{} {
	return h.cancelCh
}
