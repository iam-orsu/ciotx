package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/iam-orsu/ciotx/pkg/scanner"
)

// =====================================================================
// EVIDENCE RE-ANCHORING & VERIFICATION GATE
// =====================================================================

// VerifyAndReanchor validates each finding's evidence exists in the source file
// and re-anchors line numbers. Hallucinated findings (evidence not found) are dropped.
func VerifyAndReanchor(findings []*Finding, filesMap map[string]*scanner.SourceFile) ([]*Finding, int) {
	dropped := 0
	seen := map[string]bool{}
	var verified []*Finding

	for _, f := range findings {
		source, ok := filesMap[f.File]
		if !ok {
			dropped++
			continue
		}

		evidenceText := strings.TrimSpace(f.Evidence)
		if evidenceText == "" {
			dropped++
			continue
		}

		evLines := strings.Split(evidenceText, "\n")
		firstEv := strings.TrimSpace(evLines[0])
		if firstEv == "" {
			dropped++
			continue
		}

		matchedStart := -1
		matchedEnd := -1

		// Check candidate line_start first for locality
		candIdx := f.LineStart - 1
		if candIdx >= 0 && candIdx < len(source.Lines) && strings.Contains(source.Lines[candIdx], firstEv) {
			matchedStart = f.LineStart
			matchedEnd = f.LineStart + len(evLines) - 1
		}

		// Search ±15 lines around the candidate
		if matchedStart == -1 {
			startSearch := max(0, f.LineStart-16)
			endSearch := min(len(source.Lines), f.LineStart+15)
			for idx := startSearch; idx < endSearch; idx++ {
				if firstEv != "" && strings.Contains(source.Lines[idx], firstEv) {
					matchedStart = idx + 1
					matchedEnd = idx + len(evLines)
					break
				}
			}
		}

		// Full file search for non-trivial evidence (>= 5 chars)
		if matchedStart == -1 && len(firstEv) >= 5 {
			for idx, line := range source.Lines {
				if strings.Contains(line, firstEv) {
					matchedStart = idx + 1
					matchedEnd = idx + len(evLines)
					break
				}
			}
		}

		if matchedStart == -1 {
			dropped++
			continue
		}

		f.LineStart = matchedStart
		f.LineEnd = matchedEnd
		if f.LineEnd < f.LineStart {
			f.LineEnd = f.LineStart
		}

		// Deduplicate by (file, cwe, line_start)
		key := fmt.Sprintf("%s|%s|%d", f.File, f.CWE, f.LineStart)
		if seen[key] {
			continue
		}
		seen[key] = true
		verified = append(verified, f)
	}

	return verified, dropped
}

// =====================================================================
// ADVERSARIAL AUDIT PASS (FALSE POSITIVE FILTER)
// =====================================================================

const auditSystemPrompt = `You are a skeptical, cynical Application Security Triage Engineer.
Your job is to scrutinize candidate vulnerability findings and eliminate false positives, hallucinated issues, and unexploitable edge cases.

For each candidate finding:
1. Examine the provided file context and the reported data flow.
2. Determine if the source is truly accessible to an external untrusted caller.
3. Check if prior validation, framework sanitization, ORM safeguards, or type constraints already neutralize the threat.
4. Issue one of three verdicts:
   - "CONFIRMED": The vulnerability is verified, realistically reachable, and exploitable.
   - "REFINED": The vulnerability exists but severity or description needs adjustment.
   - "REJECTED": The finding is a false positive, unreachable code, mitigated by framework, or harmless.

RESPONSE FORMAT — strictly valid JSON:
{
  "verdicts": [
    {
      "index": 0,
      "status": "CONFIRMED",
      "refined_severity": "High",
      "justification": "Explanation of why confirmed, rejected, or refined."
    }
  ]
}`

// AuditItem is a candidate finding prepared for the audit LLM.
type AuditItem struct {
	Index          int    `json:"index"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	CWE            string `json:"cwe"`
	File           string `json:"file"`
	Lines          string `json:"lines"`
	Evidence       string `json:"evidence"`
	DataFlow       string `json:"data_flow"`
	Description    string `json:"description"`
	SurroundingCode string `json:"surrounding_code"`
}

// RunAdversarialAudit sends all verified findings to a skeptical LLM for final triage.
func RunAdversarialAudit(client *Client, findings []*Finding, filesMap map[string]*scanner.SourceFile, auditModel string, usage *Usage, usageMu interface{ Lock(); Unlock() }) ([]*Finding, int, error) {
	if len(findings) == 0 {
		return findings, 0, nil
	}

	var items []AuditItem
	for idx, f := range findings {
		ctx := ""
		if src, ok := filesMap[f.File]; ok {
			startIdx := max(0, f.LineStart-11)
			endIdx := min(len(src.Lines), f.LineEnd+10)
			var sb strings.Builder
			for i := startIdx; i < endIdx; i++ {
				sb.WriteString(fmt.Sprintf("%04d | %s\n", i+1, src.Lines[i]))
			}
			ctx = sb.String()
		}
		items = append(items, AuditItem{
			Index:           idx,
			Title:           f.Title,
			Severity:        f.Severity,
			CWE:             f.CWE,
			File:            f.File,
			Lines:           fmt.Sprintf("%d-%d", f.LineStart, f.LineEnd),
			Evidence:        f.Evidence,
			DataFlow:        f.DataFlow,
			Description:     f.Description,
			SurroundingCode: ctx,
		})
	}

	itemsJSON, _ := json.Marshal(items)
	userPrompt := fmt.Sprintf(`Review these %d candidate findings critically.
Filter out false positives, unexploitable theoretical findings, or issues mitigated by framework controls.

CANDIDATE FINDINGS:
%s

Return strictly valid JSON with {"verdicts": [{"index": 0, "status": "CONFIRMED", "refined_severity": "High", "justification": "..."}]}`, len(items), string(itemsJSON))

	messages := []Message{
		{Role: "system", Content: auditSystemPrompt},
		{Role: "user", Content: userPrompt},
	}

	content, u, err := client.Chat(auditModel, messages, true, 8192)
	if err != nil {
		// Audit failure is non-fatal; return all verified findings
		fmt.Printf("  [!] Audit pass error (falling back to verified findings): %v\n", err)
		return findings, 0, nil
	}

	usageMu.Lock()
	usage.PromptTokens += u.PromptTokens
	usage.CompletionTokens += u.CompletionTokens
	usage.CacheHitTokens += u.CacheHitTokens
	usage.CacheMissTokens += u.CacheMissTokens
	usageMu.Unlock()

	// Parse audit verdicts
	type Verdict struct {
		Index          int    `json:"index"`
		Status         string `json:"status"`
		RefinedSeverity string `json:"refined_severity"`
		Justification  string `json:"justification"`
	}
	var resp struct {
		Verdicts []Verdict `json:"verdicts"`
	}

	clean := strings.TrimSpace(content)
	if strings.Contains(clean, "```") {
		re := regexp.MustCompile("```(?:json)?\\s*")
		clean = re.ReplaceAllString(clean, "")
		re2 := regexp.MustCompile("\\s*```")
		clean = strings.TrimSpace(re2.ReplaceAllString(clean, ""))
	}

	rejected := 0
	if err := json.Unmarshal([]byte(clean), &resp); err != nil {
		// Parse failed; be lenient and keep all findings
		return findings, 0, nil
	}

	verdictMap := map[int]Verdict{}
	for _, v := range resp.Verdicts {
		verdictMap[v.Index] = v
	}

	var surviving []*Finding
	for idx, f := range findings {
		v, ok := verdictMap[idx]
		if !ok {
			// No verdict = keep
			surviving = append(surviving, f)
			continue
		}

		f.AuditStatus = strings.ToUpper(v.Status)
		f.AuditJustification = v.Justification

		switch strings.ToUpper(v.Status) {
		case "REJECTED":
			rejected++
			// Drop it
		case "REFINED":
			if v.RefinedSeverity != "" {
				f.Severity = normalizeSeverity(v.RefinedSeverity)
			}
			surviving = append(surviving, f)
		default:
			// CONFIRMED or unknown
			surviving = append(surviving, f)
		}
	}

	return surviving, rejected, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
