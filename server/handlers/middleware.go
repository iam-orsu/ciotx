// Package handlers provides HTTP middleware for the ciotx API server.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
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
				slog.Error("panic recovered",
					"req", reqID,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
			slog.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"duration_ms", time.Since(start).Milliseconds(),
				"req", reqID,
			)
		}()

		next(w, r)
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
