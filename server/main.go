// ciotx API Server
// Runs inside Docker — never exposed directly to users.
// All LLM credentials and provider details are internal to this binary.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iam-orsu/ciotx/server/handlers"
)

func main() {
	// ── Startup validation ────────────────────────────────────────────
	// Fail fast at startup rather than on first request.
	// This surfaces misconfigurations immediately when the container starts.
	if os.Getenv("LLM_API_KEY") == "" {
		fmt.Fprintln(os.Stderr, "[ciotx-server] FATAL: LLM_API_KEY environment variable is not set")
		os.Exit(1)
	}
	if os.Getenv("MASTER_LICENSE_KEY") == "" {
		fmt.Fprintln(os.Stderr, "[ciotx-server] FATAL: MASTER_LICENSE_KEY environment variable is not set")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// ── Routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Health check — used by nginx upstream healthcheck and Docker HEALTHCHECK
	mux.HandleFunc("/health", handlers.RecoveryMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"ciotx"}`)) //nolint:errcheck
	}))

	// Auth endpoint
	mux.HandleFunc("/v1/auth/verify", handlers.RecoveryMiddleware(handlers.AuthVerifyHandler))

	// Scan endpoint — auth + panic recovery
	mux.HandleFunc("/v1/scan",
		handlers.RecoveryMiddleware(handlers.AuthMiddleware(handlers.ScanHandler)),
	)

	// ── HTTP Server with proper timeouts ─────────────────────────────
	// Enterprise rule: ALWAYS set timeouts on net/http servers.
	// Default http.ListenAndServe has NO timeouts — a slow client can hold
	// connections forever and exhaust file descriptors.
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,

		// How long to wait for request headers to arrive
		ReadHeaderTimeout: 10 * time.Second,

		// Max time to read the entire request body (32MB chunks take ~1s on LAN)
		ReadTimeout: 60 * time.Second,

		// Max time to write the full response (scans can take minutes)
		WriteTimeout: 35 * time.Minute,

		// How long an idle keep-alive connection can remain open
		IdleTimeout: 120 * time.Second,
	}

	// ── Graceful shutdown ────────────────────────────────────────────
	// Listen for OS signals (Docker sends SIGTERM on `docker compose down`)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in background goroutine
	go func() {
		fmt.Printf("[ciotx-server] Listening on :%s\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[ciotx-server] Fatal: %v\n", err)
			os.Exit(1)
		}
	}()

	// Block until shutdown signal received
	sig := <-quit
	fmt.Printf("[ciotx-server] Received %s — shutting down gracefully...\n", sig)

	// Give in-flight requests 60 seconds to complete before forcing exit
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[ciotx-server] Forced shutdown: %v\n", err)
	}
	fmt.Println("[ciotx-server] Stopped.")
}
