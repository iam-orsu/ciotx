package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

const prBodySystemPrompt = `You are an Application Security Engineer writing a GitHub PR description for confirmed security findings.
Your audience is the developer who wrote the vulnerable code. Be clear, technical, and actionable.
Write valid GitHub-Flavoured Markdown. Do NOT mention any AI vendor, model name, or tool internals.
Return only the PR body markdown — no preamble, no JSON wrapping, no code fences around the whole response.`

// RunPRBody generates a markdown PR body for all security findings in one file using the audit model.
// Always returns a non-nil body — on LLM failure it falls back to a plain-text body
// so the caller is never blocked from opening the PR.
func RunPRBody(ctx context.Context, c *Client, findings []*types.Finding, fileContent string) (string, error) {
	if len(findings) == 0 {
		return "", fmt.Errorf("RunPRBody: no findings provided")
	}

	// Build a summary of all findings for the LLM prompt.
	var findingsDesc strings.Builder
	for i, f := range findings {
		findingsDesc.WriteString(fmt.Sprintf(
			"Finding %d of %d:\n"+
				"  Title:       %s\n"+
				"  CWE:         %s\n"+
				"  Severity:    %s\n"+
				"  File:        %s\n"+
				"  Lines:       %d–%d\n"+
				"  Evidence:    %s\n"+
				"  Data Flow:   %s\n"+
				"  Description: %s\n\n",
			i+1, len(findings),
			f.Title, f.CWE, f.Severity,
			f.File, f.LineStart, f.LineEnd,
			f.Evidence, f.DataFlow, f.Description,
		))
	}

	userPrompt := fmt.Sprintf(
		"Generate a GitHub PR body for %d confirmed security finding(s) in file `%s`.\n\n"+
			"%s"+
			"The PR body MUST follow this structure:\n\n"+
			"## Security Findings in `%s`\n\n"+
			"**Total:** %d finding(s)\n\n"+
			"---\n\n"+
			"For EACH finding, include a section:\n\n"+
			"### Finding N of %d — <Title> (<CWE>) · **<Severity>**\n\n"+
			"**File:** `<file>` — Lines <start>–<end>\n\n"+
			"### Vulnerable code\n"+
			"```\n<evidence>\n```\n\n"+
			"### What the vulnerability is\n"+
			"[2–3 sentence plain English explanation of the bug and how an attacker could exploit it]\n\n"+
			"### Attack scenario\n"+
			"[Concrete example: \"An attacker could send...\" showing a real exploitation path]\n\n"+
			"### Recommended remediation\n"+
			"[Specific verbal guidance — do NOT include code. Explain what pattern to use, what to avoid, and why.]\n\n"+
			"### References\n"+
			"- [<CWE>](<MITRE URL>)\n\n"+
			"---\n\n"+
			"After all findings, end with:\n"+
			"*This PR was opened automatically by ciotx. No code has been modified — remediation is at the developer's discretion.*",
		len(findings), findings[0].File,
		findingsDesc.String(),
		findings[0].File, len(findings), len(findings),
	)

	content, _, err := c.Chat(ctx, modelAudit, NewMessages(prBodySystemPrompt, userPrompt), false, 6000)
	if err != nil {
		return fallbackPRBody(findings), fmt.Errorf("pr body generation failed: %w", err)
	}

	body := strings.TrimSpace(content)
	if body == "" {
		return fallbackPRBody(findings), nil
	}
	return body, nil
}

func fallbackPRBody(findings []*types.Finding) string {
	if len(findings) == 0 {
		return "## Security Findings\n\n*No findings available.*"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Security Findings in `%s`\n\n", findings[0].File))
	sb.WriteString(fmt.Sprintf("**Total:** %d finding(s)\n\n---\n\n", len(findings)))

	for i, f := range findings {
		cweURL := cweLink(f.CWE)
		sb.WriteString(fmt.Sprintf(
			"### Finding %d of %d — %s (%s) · **%s**\n\n"+
				"**File:** `%s` — Lines %d–%d\n\n"+
				"### Vulnerable code\n```\n%s\n```\n\n"+
				"### Description\n%s\n\n"+
				"### References\n- [%s](%s)\n\n---\n\n",
			i+1, len(findings),
			f.Title, f.CWE, f.Severity,
			f.File, f.LineStart, f.LineEnd,
			f.Evidence, f.Description,
			f.CWE, cweURL,
		))
	}

	sb.WriteString("*This PR was opened automatically by ciotx. No code has been modified.*")
	return sb.String()
}

// cweLink converts a CWE string (e.g. "CWE-89: SQL Injection" or "CWE-89")
// into the MITRE CWE reference URL.
func cweLink(cwe string) string {
	id := cwe
	if i := strings.Index(cwe, ":"); i != -1 {
		id = strings.TrimSpace(cwe[:i])
	}
	id = strings.TrimPrefix(strings.TrimPrefix(id, "CWE-"), "cwe-")
	if id == "" || id == cwe {
		return "https://cwe.mitre.org/"
	}
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", id)
}
