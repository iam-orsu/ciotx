// ciotx API Server
// Runs inside Docker — never exposed directly to users.
// All LLM credentials and provider details are internal to this binary.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/iam-orsu/ciotx/server/handlers"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// Health check — used by nginx upstream check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"ciotx"}`))
	})

	// Auth endpoints
	mux.HandleFunc("/v1/auth/verify", handlers.AuthVerifyHandler)

	// Scan endpoint — protected by license key auth middleware
	mux.HandleFunc("/v1/scan", handlers.AuthMiddleware(handlers.ScanHandler))

	fmt.Printf("[ciotx-server] Listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintf(os.Stderr, "[ciotx-server] Fatal: %v\n", err)
		os.Exit(1)
	}
}
