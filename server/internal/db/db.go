// Package db manages the PostgreSQL connection pool and schema migrations.
// It is internal to the server — never referenced by the CLI or exposed in API responses.
package db

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

// Init opens the connection pool and verifies connectivity.
// Call once at server startup before serving any requests.
func Init(ctx context.Context) error {
	dsn := buildDSN()
	if dsn == "" {
		return fmt.Errorf("no database configuration found — set DATABASE_URL or POSTGRES_* env vars")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parse database config: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 2

	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open database pool: %w", err)
	}

	if err := p.Ping(ctx); err != nil {
		p.Close()
		return fmt.Errorf("ping database: %w", err)
	}

	pool = p
	fmt.Println("[db] connected to PostgreSQL")
	return nil
}

// Pool returns the active connection pool.
// Panics if Init has not been called — deliberate: a missing DB is a fatal misconfiguration.
func Pool() *pgxpool.Pool {
	if pool == nil {
		panic("[db] Pool() called before Init()")
	}
	return pool
}

// IsAvailable reports whether the DB pool was successfully initialized.
// Use this before calling Pool() in contexts where DB unavailability is non-fatal.
func IsAvailable() bool { return pool != nil }

// Close drains the pool. Call during graceful shutdown.
func Close() {
	if pool != nil {
		pool.Close()
	}
}

// buildDSN constructs a DSN from DATABASE_URL (preferred) or individual POSTGRES_* vars.
// Uses url.URL to safely encode the password — avoids DSN injection from special chars.
func buildDSN() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}

	host := getenv("POSTGRES_HOST", "postgres")
	port := getenv("POSTGRES_PORT", "5432")
	user := getenv("POSTGRES_USER", "ciotx")
	password := os.Getenv("POSTGRES_PASSWORD")
	dbname := getenv("POSTGRES_DB", "ciotx")

	if password == "" {
		return ""
	}

	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     net.JoinHostPort(host, port),
		Path:     "/" + dbname,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
