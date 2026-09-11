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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iam-orsu/ciotx/server/admin"
	"github.com/iam-orsu/ciotx/server/handlers"
	"github.com/iam-orsu/ciotx/server/internal/db"
	"github.com/iam-orsu/ciotx/server/worker"
)

// adminLicensesRouter dispatches GET and POST on /admin/api/licenses.
func adminLicensesRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handlers.AdminListLicensesHandler(w, r)
	case http.MethodPost:
		handlers.AdminCreateLicenseHandler(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	// ── Admin CLI dispatch ────────────────────────────────────────────
	// If the first argument is a known admin subcommand, run it and exit.
	// This turns the server binary into a dual-purpose operator tool.
	if len(os.Args) > 1 && os.Args[1] == "license" {
		admin.RunLicenseCLI(os.Args[2:])
		return
	}

	// ── Structured logging ────────────────────────────────────────────
	// JSON lines to stdout — pipe-friendly and parseable by log aggregators.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// ── Startup validation ────────────────────────────────────────────
	if os.Getenv("LLM_API_KEY") == "" {
		slog.Error("missing required environment variable", "var", "LLM_API_KEY")
		os.Exit(1)
	}
	if os.Getenv("MASTER_LICENSE_KEY") == "" {
		slog.Error("missing required environment variable", "var", "MASTER_LICENSE_KEY")
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
		// Non-fatal: master key fallback still works without Postgres.
		slog.Warn("database unavailable — DB-backed licenses will not work", "error", err)
	} else {
		if err := db.RunMigrations(startCtx); err != nil {
			slog.Error("migration failed", "error", err)
			os.Exit(1)
		}
	}

	// ── GitHub scan workers (Phase 6) ────────────────────────────────
	// Workers process async scan_jobs enqueued by the /webhooks/github handler.
	// They run as background goroutines and stop when the server shuts down.
	// Only started when the GitHub App is configured (GITHUB_APP_ID set).
	if os.Getenv("GITHUB_APP_ID") != "" {
		workerCtx, workerCancel := context.WithCancel(context.Background())
		defer workerCancel()
		worker.Start(workerCtx, 2)
		slog.Info("github scan workers started", "count", 2)
	} else {
		slog.Info("GITHUB_APP_ID not set — GitHub PR integration disabled")
	}

	// ── Routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// ── Public marketing homepage ─────────────────────────────────
	mux.HandleFunc("/", handlers.RecoveryMiddleware(handlers.HomeHandler))

	mux.HandleFunc("/health", handlers.RecoveryMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"ciotx"}`)) //nolint:errcheck
	}))

	mux.HandleFunc("/v1/auth/verify", handlers.RecoveryMiddleware(handlers.AuthVerifyHandler))

	mux.HandleFunc("/v1/scan",
		handlers.RecoveryMiddleware(handlers.AuthMiddleware(handlers.ScanHandler)),
	)

	mux.HandleFunc("/v1/status",
		handlers.RecoveryMiddleware(handlers.AuthMiddleware(handlers.StatusHandler)),
	)

	mux.HandleFunc("/v1/history",
		handlers.RecoveryMiddleware(handlers.AuthMiddleware(handlers.HistoryHandler)),
	)

	// ── GitHub Webhook (Phase 6) ─────────────────────────────────────
	// HMAC-verified endpoint — GitHub sends push/installation events here.
	mux.HandleFunc("/webhooks/github", handlers.RecoveryMiddleware(handlers.WebhookHandler))

	// ── Admin Web UI (Phase 4) ────────────────────────────────────────
	// The admin panel is only active when ADMIN_PASSWORD is set.
	// Login/logout are unprotected (they establish the session).
	// All /admin/api/* routes require a valid HMAC session cookie.
	mux.HandleFunc("/admin", handlers.RecoveryMiddleware(handlers.AdminUIHandler))
	mux.HandleFunc("/admin/login", handlers.RecoveryMiddleware(handlers.AdminLoginHandler))
	mux.HandleFunc("/admin/logout", handlers.RecoveryMiddleware(handlers.AdminLogoutHandler))
	mux.HandleFunc("/admin/api/stats",
		handlers.RecoveryMiddleware(handlers.AdminAuthMiddleware(handlers.AdminStatsHandler)))
	mux.HandleFunc("/admin/api/licenses",
		handlers.RecoveryMiddleware(handlers.AdminAuthMiddleware(adminLicensesRouter)))
	mux.HandleFunc("/admin/api/licenses/",
		handlers.RecoveryMiddleware(handlers.AdminAuthMiddleware(handlers.AdminRevokeLicenseHandler)))
	mux.HandleFunc("/admin/api/scans",
		handlers.RecoveryMiddleware(handlers.AdminAuthMiddleware(handlers.AdminScansHandler)))

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
		slog.Info("listening", "port", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	slog.Info("shutting down gracefully", "signal", sig.String())

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer shutCancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		slog.Error("forced shutdown", "error", err)
	}

	db.Close()
	slog.Info("stopped")
}
