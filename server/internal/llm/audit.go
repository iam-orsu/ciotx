package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

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
      "justification": "Explanation."
    }
  ]
}`

// RunAudit sends verified findings to a skeptical internal model to filter false positives.
func RunAudit(ctx context.Context, client *Client, findings []*types.Finding, filesContent map[string][]string, usage *Usage, usageMu interface{ Lock(); Unlock() }) ([]*types.Finding, int, error) {
	if len(findings) == 0 {
		return findings, 0, nil
	}

	type auditItem struct {
		Index           int    `json:"index"`
		Title           string `json:"title"`
		Severity        string `json:"severity"`
		CWE             string `json:"cwe"`
		File            string `json:"file"`
		Lines           string `json:"lines"`
		Evidence        string `json:"evidence"`
		DataFlow        string `json:"data_flow"`
		Description     string `json:"description"`
		SurroundingCode string `json:"surrounding_code"`
	}

	var items []auditItem
	for idx, f := range findings {
		surroundingCode := ""
		if lines, ok := filesContent[f.File]; ok {
			startIdx := max(0, f.LineStart-11)
			endIdx := min(len(lines), f.LineEnd+10)
			var sb strings.Builder
			for i := startIdx; i < endIdx; i++ {
				sb.WriteString(fmt.Sprintf("%04d | %s\n", i+1, lines[i]))
			}
			surroundingCode = sb.String()
		}
		items = append(items, auditItem{
			Index:           idx,
			Title:           f.Title,
			Severity:        f.Severity,
			CWE:             f.CWE,
			File:            f.File,
			Lines:           fmt.Sprintf("%d-%d", f.LineStart, f.LineEnd),
			Evidence:        f.Evidence,
			DataFlow:        f.DataFlow,
			Description:     f.Description,
			SurroundingCode: surroundingCode,
		})
	}

	itemsJSON, _ := json.Marshal(items)
	userPrompt := fmt.Sprintf(`Review these %d candidate findings critically.
Filter false positives, unexploitable theoretical findings, or issues mitigated by framework controls.

CANDIDATE FINDINGS:
%s

Return strictly valid JSON with {"verdicts": [...]}`, len(items), string(itemsJSON))

	msgs := NewMessages(auditSystemPrompt, userPrompt)
	content, u, err := client.Chat(ctx, modelAudit, msgs, true, 8192)
	if err != nil {
		// Non-fatal: return all verified findings if audit fails
		return findings, 0, nil
	}

	usageMu.Lock()
	usage.PromptTokens += u.PromptTokens
	usage.CompletionTokens += u.CompletionTokens
	usage.CacheHitTokens += u.CacheHitTokens
	usage.CacheMissTokens += u.CacheMissTokens
	usageMu.Unlock()

	type verdict struct {
		Index           int    `json:"index"`
		Status          string `json:"status"`
		RefinedSeverity string `json:"refined_severity"`
		Justification   string `json:"justification"`
	}
	var resp struct {
		Verdicts []verdict `json:"verdicts"`
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
		return findings, 0, nil
	}

	verdictMap := map[int]verdict{}
	for _, v := range resp.Verdicts {
		verdictMap[v.Index] = v
	}

	var surviving []*types.Finding
	for idx, f := range findings {
		v, ok := verdictMap[idx]
		if !ok {
			surviving = append(surviving, f)
			continue
		}
		f.AuditStatus = strings.ToUpper(v.Status)
		f.AuditJustification = v.Justification

		switch strings.ToUpper(v.Status) {
		case "REJECTED":
			rejected++
		case "REFINED":
			if v.RefinedSeverity != "" {
				f.Severity = normalizeSeverity(v.RefinedSeverity)
			}
			surviving = append(surviving, f)
		default:
			surviving = append(surviving, f)
		}
	}

	return surviving, rejected, nil
}

