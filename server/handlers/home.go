package handlers

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"os"
)

//go:embed home_ui/home.html
var homeHTMLRaw string

var homeTmpl = template.Must(template.New("home").Parse(homeHTMLRaw))

type homeData struct {
	Domain string
}

// HomeHandler serves the public marketing homepage at /.
// DOMAIN_NAME from the environment is injected into the template so the
// install command always reflects the operator's actual domain.
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	domain := os.Getenv("DOMAIN_NAME")
	if domain == "" {
		domain = "your-domain.com"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)

	if err := homeTmpl.Execute(w, homeData{Domain: domain}); err != nil {
		slog.Error("home template execute failed", "error", err)
	}
}
