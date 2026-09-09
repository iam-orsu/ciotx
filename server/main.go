// ciotx API Server
// Runs inside Docker — never exposed directly to users.
// All LLM credentials and provider details are internal to this binary.
//
// Usage (server mode):
//
//	ciotx-server
//
// Usage (admin CLI):
//
//	ciotx-server license create --org "Acme" --email sec@acme.com --plan pro --scans 500
//	ciotx-server license revoke <key>
//	ciotx-server license list
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iam-orsu/ciotx/server/admin"
	"github.com/iam-orsu/ciotx/server/handlers"
	"github.com/iam-orsu/ciotx/server/internal/db"
)

func main() {
	// ── Admin CLI dispatch ────────────────────────────────────────────
	// If the first argument is a known admin subcommand, run it and exit.
	// This turns the server binary into a dual-purpose operator tool.
	if len(os.Args) > 1 && os.Args[1] == "license" {
		admin.RunLicenseCLI(os.Args[2:])
		return
	}

	// ── Startup validation ────────────────────────────────────────────
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

	// ── Database ─────────────────────────────────────────────────────
	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()

	if err := db.Init(startCtx); err != nil {
		// DB is required in Phase 2 — but we log a warning and continue so that
		// the master key fallback still works during local dev without Postgres.
		fmt.Printf("[ciotx-server] WARNING: database unavailable (%v) — DB-backed licenses will not work\n", err)
	} else {
		if err := db.RunMigrations(startCtx); err != nil {
			fmt.Fprintf(os.Stderr, "[ciotx-server] FATAL: migration failed: %v\n", err)
			os.Exit(1)
		}
	}

	// ── Routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()

	mux.HandleFunc("/health", handlers.RecoveryMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"ciotx"}`)) //nolint:errcheck
	}))

	mux.HandleFunc("/v1/auth/verify", handlers.RecoveryMiddleware(handlers.AuthVerifyHandler))

	mux.HandleFunc("/v1/scan",
		handlers.RecoveryMiddleware(handlers.AuthMiddleware(handlers.ScanHandler)),
	)

	// ── HTTP Server ───────────────────────────────────────────────────
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      35 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	// ── Graceful shutdown ─────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("[ciotx-server] Listening on :%s\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[ciotx-server] Fatal: %v\n", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	fmt.Printf("[ciotx-server] Received %s — shutting down gracefully...\n", sig)

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer shutCancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		fmt.Fprintf(os.Stderr, "[ciotx-server] Forced shutdown: %v\n", err)
	}

	db.Close()
	fmt.Println("[ciotx-server] Stopped.")
}
