// Package handlers provides HTTP middleware for the ciotx API server.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"
)

// RecoveryMiddleware catches any panic in a handler, logs the stack trace
// server-side, and returns a generic 500 to the client.
// This prevents a nil pointer or any other panic from crashing the server process.
func RecoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()
		start := time.Now()

		// Attach request ID to the response so ops can correlate with server logs
		w.Header().Set("X-Request-ID", reqID)

		defer func() {
			if rec := recover(); rec != nil {
				// Log full stack trace server-side only — never expose to client
				fmt.Printf("[ciotx-server] PANIC [req=%s] %v\n%s\n", reqID, rec, debug.Stack())
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()

		next(w, r)

		// Structured access log: method, path, duration, request ID
		fmt.Printf("[ciotx-server] %s %s %s [req=%s]\n",
			r.Method, r.URL.Path,
			time.Since(start).Round(time.Millisecond),
			reqID,
		)
	}
}

// newRequestID generates a short random hex string for request tracing.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}
