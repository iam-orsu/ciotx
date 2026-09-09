package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/iam-orsu/ciotx/pkg/llm"
)

// ScanStats tracks runtime metrics for the report.
type ScanStats struct {
	TotalFiles        int
	TotalLines        int
	TotalTokensEst    int
	PromptTokens      int
	CompletionTokens  int
	CacheHitTokens    int
	CacheMissTokens   int
	HallucinationsDropped int
	AuditRejected     int
	DurationSeconds   float64
	EstimatedCostUSD  float64
}

// =====================================================================
// JSON REPORT
// =====================================================================

// WriteJSON saves findings to a JSON file.
func WriteJSON(findings []*llm.Finding, outputPath string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0o644)
}

// =====================================================================
// HTML REPORT
// =====================================================================

// WriteHTML generates an interactive HTML security report.
func WriteHTML(findings []*llm.Finding, stats *ScanStats, targetDir, outputPath string) error {
	// Count by severity
	counts := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Sort findings: Critical > High > Medium > Low
	sorted := make([]*llm.Finding, len(findings))
	copy(sorted, findings)
	severityOrder := map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
	sort.Slice(sorted, func(i, j int) bool {
		return severityOrder[sorted[i].Severity] < severityOrder[sorted[j].Severity]
	})

	var cards strings.Builder
	for i, f := range sorted {
		sevClass := strings.ToLower(f.Severity)
		auditBadge := ""
		if f.AuditStatus != "" {
			auditBadge = fmt.Sprintf(`<span class="audit-badge audit-%s">%s</span>`,
				strings.ToLower(f.AuditStatus), f.AuditStatus)
		}
		cards.WriteString(fmt.Sprintf(`
  <div class="finding-card" data-severity="%s">
    <div class="finding-header" onclick="toggleFinding(%d)">
      <div class="finding-title-group">
        <span class="sev-badge sev-%s">%s</span>
        <span class="finding-title">%s</span>
        %s
      </div>
      <div class="finding-meta">
        <span class="finding-file">%s</span>
        <span class="finding-lines">L%d–%d</span>
        <span class="caret" id="caret-%d">&#9660;</span>
      </div>
    </div>
    <div class="finding-body" id="body-%d" style="display:none;">
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">CWE Classification</div>
          <div class="detail-value">%s</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Attack Data Flow</div>
          <div class="detail-value">%s</div>
        </div>
        <div class="detail-item detail-full">
          <div class="detail-label">Technical Description</div>
          <div class="detail-value">%s</div>
        </div>
        <div class="detail-item detail-full">
          <div class="detail-label">Vulnerable Evidence</div>
          <pre class="code-block">%s</pre>
        </div>
        <div class="detail-item detail-full">
          <div class="detail-label">Recommended Remediation</div>
          <pre class="code-block remediation">%s</pre>
        </div>
        %s
      </div>
    </div>
  </div>`,
			f.Severity, i, sevClass, f.Severity, html.EscapeString(f.Title), auditBadge,
			html.EscapeString(f.File), f.LineStart, f.LineEnd, i, i,
			html.EscapeString(f.CWE),
			html.EscapeString(f.DataFlow),
			html.EscapeString(f.Description),
			html.EscapeString(f.Evidence),
			html.EscapeString(f.Remediation),
			func() string {
				if f.AuditJustification != "" {
					return fmt.Sprintf(`<div class="detail-item detail-full"><div class="detail-label">Audit Justification</div><div class="detail-value">%s</div></div>`, html.EscapeString(f.AuditJustification))
				}
				return ""
			}(),
		))
	}

	// Empty state
	if len(sorted) == 0 {
		cards.WriteString(`
  <div class="empty-state">
    <div class="empty-icon">&#10003;</div>
    <div class="empty-title">No Vulnerabilities Found</div>
    <div class="empty-subtitle">The codebase passed all security checks in this scan.</div>
  </div>`)
	}

	reportHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ciotx Security Report</title>
  <style>
    :root {
      --bg: #0d1117; --card: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
      --crit: #f85149; --high: #f0883e; --med: #d29922; --low: #3fb950;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }
    .header { background: linear-gradient(135deg, #0d1117 0%%, #161b22 100%%); border-bottom: 1px solid var(--border); padding: 32px 40px; }
    .header h1 { font-size: 28px; font-weight: 700; color: #58a6ff; letter-spacing: -0.5px; }
    .header h1 span { color: var(--text); }
    .header-meta { margin-top: 8px; color: var(--muted); font-size: 14px; }
    .main { padding: 32px 40px; max-width: 1400px; margin: 0 auto; }
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .metric-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; cursor: pointer; transition: all 0.2s; text-align: center; }
    .metric-card:hover { border-color: var(--accent); transform: translateY(-2px); }
    .metric-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 8px; }
    .metric-val { font-size: 36px; font-weight: 700; }
    .val-total { color: var(--accent); }
    .val-crit { color: var(--crit); }
    .val-high { color: var(--high); }
    .val-med { color: var(--med); }
    .val-low { color: var(--low); }
    .stats-bar { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px 28px; margin-bottom: 28px; display: flex; gap: 40px; flex-wrap: wrap; }
    .stat { display: flex; flex-direction: column; }
    .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; }
    .stat-value { font-size: 18px; font-weight: 600; color: var(--text); margin-top: 2px; }
    .toolbar { display: flex; gap: 16px; align-items: center; margin-bottom: 24px; flex-wrap: wrap; }
    .search-box input { background: var(--card); border: 1px solid var(--border); color: var(--text); border-radius: 8px; padding: 10px 16px; font-size: 14px; width: 360px; outline: none; transition: border-color 0.2s; }
    .search-box input:focus { border-color: var(--accent); }
    .filter-group { display: flex; gap: 8px; flex-wrap: wrap; }
    .filter-btn { background: var(--card); border: 1px solid var(--border); color: var(--muted); border-radius: 6px; padding: 8px 16px; font-size: 13px; cursor: pointer; transition: all 0.2s; }
    .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(88,166,255,0.08); }
    .findings-container { display: flex; flex-direction: column; gap: 12px; }
    .finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; transition: border-color 0.2s; }
    .finding-card:hover { border-color: rgba(88,166,255,0.4); }
    .finding-card[data-severity="Critical"] { border-left: 4px solid var(--crit); }
    .finding-card[data-severity="High"] { border-left: 4px solid var(--high); }
    .finding-card[data-severity="Medium"] { border-left: 4px solid var(--med); }
    .finding-card[data-severity="Low"] { border-left: 4px solid var(--low); }
    .finding-header { padding: 18px 24px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; gap: 16px; }
    .finding-title-group { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .finding-title { font-size: 15px; font-weight: 600; }
    .sev-badge { font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px; }
    .sev-critical { background: rgba(248,81,73,0.15); color: var(--crit); border: 1px solid rgba(248,81,73,0.3); }
    .sev-high { background: rgba(240,136,62,0.15); color: var(--high); border: 1px solid rgba(240,136,62,0.3); }
    .sev-medium { background: rgba(210,153,34,0.15); color: var(--med); border: 1px solid rgba(210,153,34,0.3); }
    .sev-low { background: rgba(63,185,80,0.15); color: var(--low); border: 1px solid rgba(63,185,80,0.3); }
    .audit-badge { font-size: 11px; padding: 3px 10px; border-radius: 20px; background: rgba(88,166,255,0.1); color: var(--accent); border: 1px solid rgba(88,166,255,0.2); }
    .finding-meta { display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13px; flex-shrink: 0; }
    .finding-file { font-family: monospace; font-size: 12px; }
    .finding-lines { font-family: monospace; font-size: 12px; }
    .caret { font-size: 12px; transition: transform 0.2s; }
    .caret.open { transform: rotate(180deg); }
    .finding-body { padding: 0 24px 24px; border-top: 1px solid var(--border); margin-top: 0; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
    .detail-full { grid-column: 1 / -1; }
    .detail-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); margin-bottom: 6px; font-weight: 600; }
    .detail-value { font-size: 14px; color: var(--text); }
    .code-block { background: #0d1117; border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; color: #e6edf3; line-height: 1.6; }
    .code-block.remediation { border-color: rgba(63,185,80,0.3); background: rgba(63,185,80,0.03); }
    .empty-state { text-align: center; padding: 80px 40px; color: var(--muted); }
    .empty-icon { font-size: 64px; color: var(--low); margin-bottom: 16px; }
    .empty-title { font-size: 22px; font-weight: 600; color: var(--text); margin-bottom: 8px; }
    .footer { border-top: 1px solid var(--border); padding: 24px 40px; text-align: center; color: var(--muted); font-size: 13px; margin-top: 48px; }
    @media (max-width: 768px) { .main { padding: 16px; } .header { padding: 20px; } .detail-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="header">
    <h1>ciotx <span>Security Report</span></h1>
    <div class="header-meta">
      Target: %s &nbsp;|&nbsp; Generated: %s &nbsp;|&nbsp; Scan Duration: %.1fs
    </div>
  </div>

  <div class="main">
    <div class="metrics">
      <div class="metric-card" onclick="filterBySeverity('all')">
        <div class="metric-label">Total Findings</div>
        <div class="metric-val val-total">%d</div>
      </div>
      <div class="metric-card" onclick="filterBySeverity('Critical')">
        <div class="metric-label">Critical</div>
        <div class="metric-val val-crit">%d</div>
      </div>
      <div class="metric-card" onclick="filterBySeverity('High')">
        <div class="metric-label">High</div>
        <div class="metric-val val-high">%d</div>
      </div>
      <div class="metric-card" onclick="filterBySeverity('Medium')">
        <div class="metric-label">Medium</div>
        <div class="metric-val val-med">%d</div>
      </div>
      <div class="metric-card" onclick="filterBySeverity('Low')">
        <div class="metric-label">Low</div>
        <div class="metric-val val-low">%d</div>
      </div>
    </div>

    <div class="stats-bar">
      <div class="stat"><div class="stat-label">Files Scanned</div><div class="stat-value">%d</div></div>
      <div class="stat"><div class="stat-label">Total Lines</div><div class="stat-value">%s</div></div>
      <div class="stat"><div class="stat-label">Hallucinations Dropped</div><div class="stat-value">%d</div></div>
      <div class="stat"><div class="stat-label">False Positives Filtered</div><div class="stat-value">%d</div></div>
      <div class="stat"><div class="stat-label">Est. API Cost</div><div class="stat-value">$%.4f</div></div>
    </div>

    <div class="toolbar">
      <div class="search-box">
        <input type="text" id="search-input" placeholder="Search findings by title, file, CWE..." oninput="handleSearch()">
      </div>
      <div class="filter-group">
        <button class="filter-btn active" id="btn-all" onclick="filterBySeverity('all')">All</button>
        <button class="filter-btn" id="btn-crit" onclick="filterBySeverity('Critical')">Critical</button>
        <button class="filter-btn" id="btn-high" onclick="filterBySeverity('High')">High</button>
        <button class="filter-btn" id="btn-med" onclick="filterBySeverity('Medium')">Medium</button>
        <button class="filter-btn" id="btn-low" onclick="filterBySeverity('Low')">Low</button>
      </div>
    </div>

    <div class="findings-container" id="findings-list">
      %s
    </div>
  </div>

  <div class="footer">
    Powered by <strong>ciotx</strong> &mdash; Autonomous Deep-Reasoning Security Auditor &mdash; <a href="https://github.com/iam-orsu/ciotx" style="color: var(--accent);">github.com/iam-orsu/ciotx</a>
  </div>

  <script>
    let activeFilter = 'all';
    function toggleFinding(i) {
      var body = document.getElementById('body-' + i);
      var caret = document.getElementById('caret-' + i);
      if (body.style.display === 'none') {
        body.style.display = 'block';
        caret.classList.add('open');
      } else {
        body.style.display = 'none';
        caret.classList.remove('open');
      }
    }
    function filterBySeverity(sev) {
      activeFilter = sev;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      var id = sev === 'all' ? 'btn-all' : 'btn-' + sev.toLowerCase().substring(0,4);
      var btn = document.getElementById(id);
      if (btn) btn.classList.add('active');
      applyFilters();
    }
    function handleSearch() { applyFilters(); }
    function applyFilters() {
      var query = document.getElementById('search-input').value.toLowerCase();
      document.querySelectorAll('.finding-card').forEach(function(card) {
        var sev = card.getAttribute('data-severity');
        var text = card.textContent.toLowerCase();
        var sevMatch = activeFilter === 'all' || sev === activeFilter;
        var textMatch = query === '' || text.includes(query);
        card.style.display = (sevMatch && textMatch) ? 'block' : 'none';
      });
    }
  </script>
</body>
</html>`,
		html.EscapeString(targetDir),
		time.Now().Format("2006-01-02 15:04:05"),
		stats.DurationSeconds,
		len(findings),
		counts["Critical"], counts["High"], counts["Medium"], counts["Low"],
		stats.TotalFiles,
		formatNumber(stats.TotalLines),
		stats.HallucinationsDropped,
		stats.AuditRejected,
		stats.EstimatedCostUSD,
		cards.String(),
	)

	return os.WriteFile(outputPath, []byte(reportHTML), 0o644)
}

func formatNumber(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
