package handlers

import (
	"net/http"
	"strconv"

	"github.com/iam-orsu/ciotx/server/internal/db"
)

type scanHistoryItem struct {
	FindingsCount int    `json:"findings_count"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	DurationMS    int64  `json:"duration_ms"`
	ClientVersion string `json:"client_version"`
	CreatedAt     string `json:"created_at"`
}

type historyResponse struct {
	Records []*scanHistoryItem `json:"records"`
}

// HistoryHandler returns the authenticated user's recent scan records.
// Protected by AuthMiddleware — license is always present in context.
// Query param: limit (1–50, default 10).
func HistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	license := licenseFromContext(r.Context())
	if license == nil {
		// Master key has no license record; return empty history.
		writeJSON(w, http.StatusOK, historyResponse{Records: []*scanHistoryItem{}})
		return
	}

	limit := 10
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if n, err := strconv.Atoi(lStr); err == nil && n >= 1 && n <= 50 {
			limit = n
		}
	}

	records, err := db.GetScanHistory(r.Context(), license.ID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch scan history")
		return
	}

	items := make([]*scanHistoryItem, 0, len(records))
	for _, rec := range records {
		items = append(items, &scanHistoryItem{
			FindingsCount: rec.FindingsCount,
			CriticalCount: rec.CriticalCount,
			HighCount:     rec.HighCount,
			DurationMS:    rec.DurationMS,
			ClientVersion: rec.ClientVersion,
			CreatedAt:     rec.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
		})
	}

	writeJSON(w, http.StatusOK, historyResponse{Records: items})
}
