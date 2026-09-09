package handlers

import (
	"net/http"
	"time"
)

func formatDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02")
	return &s
}

type statusResponse struct {
	Plan             string  `json:"plan"`
	Organization     string  `json:"organization"`
	ScansThisMonth   int     `json:"scans_this_month"`
	MaxScansPerMonth int     `json:"max_scans_per_month"`
	ExpiresAt        *string `json:"expires_at,omitempty"` // "YYYY-MM-DD" or absent
	IsActive         bool    `json:"is_active"`
}

// StatusHandler returns the authenticated user's plan and quota information.
// Protected by AuthMiddleware — license is always present in context.
func StatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	license := licenseFromContext(r.Context())
	if license == nil {
		// Master key — operator bypass, no quota enforced.
		writeJSON(w, http.StatusOK, statusResponse{
			Plan:             "master",
			Organization:     "operator",
			MaxScansPerMonth: -1,
			IsActive:         true,
		})
		return
	}

	// Apply the same lazy monthly reset logic as IsQuotaExceeded:
	// if scan_month doesn't match the current month, counter is effectively 0.
	scansThisMonth := license.ScansThisMonth
	if license.ScanMonth != time.Now().UTC().Format("2006-01") {
		scansThisMonth = 0
	}

	writeJSON(w, http.StatusOK, statusResponse{
		Plan:             license.Plan,
		Organization:     license.Organization,
		ScansThisMonth:   scansThisMonth,
		MaxScansPerMonth: license.MaxScansPerMonth,
		ExpiresAt:        formatDate(license.ExpiresAt),
		IsActive:         license.IsActive,
	})
}
