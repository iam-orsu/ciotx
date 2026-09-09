package handlers

import (
	"context"

	"github.com/iam-orsu/ciotx/server/internal/db"
)

// contextKey is an unexported type for keys in request contexts.
// Using a private type prevents collisions with other packages.
type contextKey int

const licenseKey contextKey = iota

// withLicense attaches a License to the request context.
func withLicense(ctx context.Context, l *db.License) context.Context {
	return context.WithValue(ctx, licenseKey, l)
}

// licenseFromContext extracts the License attached by AuthMiddleware.
// Returns nil when the request was authenticated via the master key (admin bypass).
func licenseFromContext(ctx context.Context) *db.License {
	l, _ := ctx.Value(licenseKey).(*db.License)
	return l
}
