package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

const prBodySystemPrompt = `You are writing a GitHub pull request description to warn a developer about a security problem in their code.

Your audience is a developer who may not have a security background. Write as if you are explaining the problem to a smart colleague over chat.

RULES - follow all of them strictly:
1. Use plain, everyday English. Pretend you are talking to someone who has never heard of "attack vectors", "threat actors", or "CVEs".
2. No em-dashes (—). Use a regular hyphen (-) or a colon (:) instead.
3. No jargon. Instead of "SQL injection via unsanitized parameter", say "user input is dropped directly into a database query without any safety checks".
4. Keep every sentence short. Break long ideas into two sentences.
5. The "What is wrong" section explains the problem like a story: what the code does now, why that is dangerous, what could go wrong.
6. The "How someone could misuse this" section is a one-paragraph real story: "Imagine someone sends the app a request like... This would cause...".
7. The "How to fix it" section gives clear, step-by-step guidance a developer can act on immediately. No code samples. Plain words only.
8. Do NOT mention any AI vendor, model name, or tool internals.
9. Write valid GitHub-Flavoured Markdown.
10. Return only the PR body - no preamble, no JSON, no code fences wrapping the whole response.`

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
				"  Lines:       %d-%d\n"+
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
		"Write a GitHub PR body for %d security problem(s) found in `%s`.\n\n"+
			"%s"+
			"The PR body MUST follow this exact structure:\n\n"+
			"## Security Problems in `%s`\n\n"+
			"**%d problem(s) found** - please read and fix before merging.\n\n"+
			"---\n\n"+
			"For EACH finding, write a section using this layout:\n\n"+
			"### Problem 1 of %d: <Title> (<CWE>) - **<Severity>**\n\n"+
			"**File:** `<file>`, lines <start>-<end>\n\n"+
			"#### The code that has the problem\n"+
			"```\n<evidence>\n```\n\n"+
			"#### What is wrong\n"+
			"[2-3 short sentences in plain English. Explain what the code does, why that is unsafe, and what could happen if someone exploits it. No jargon.]\n\n"+
			"#### How someone could misuse this\n"+
			"[One paragraph starting with 'Imagine someone...' or 'If an attacker...'. Make it concrete and easy to picture. No technical terms.]\n\n"+
			"#### How to fix it\n"+
			"[3-5 bullet points with clear, simple steps. Start each bullet with a verb. No code samples. Plain words only.]\n\n"+
			"#### More information\n"+
			"- [%s](<MITRE URL for this CWE>)\n\n"+
			"---\n\n"+
			"After all problems, end with this exact line:\n"+
			"*Opened automatically by ciotx. No code has been changed - this is a heads-up only.*",
		len(findings), findings[0].File,
		findingsDesc.String(),
		findings[0].File, len(findings),
		len(findings),
		findings[0].CWE,
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
		return "## Security Problems\n\n*No findings available.*"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Security Problems in `%s`\n\n", findings[0].File))
	sb.WriteString(fmt.Sprintf("**%d problem(s) found** - please read and fix before merging.\n\n---\n\n", len(findings)))

	for i, f := range findings {
		cweURL := cweLink(f.CWE)
		sb.WriteString(fmt.Sprintf(
			"### Problem %d of %d: %s (%s) - **%s**\n\n"+
				"**File:** `%s`, lines %d-%d\n\n"+
				"#### The code that has the problem\n```\n%s\n```\n\n"+
				"#### What is wrong\n%s\n\n"+
				"#### More information\n- [%s](%s)\n\n---\n\n",
			i+1, len(findings),
			f.Title, f.CWE, f.Severity,
			f.File, f.LineStart, f.LineEnd,
			f.Evidence, f.Description,
			f.CWE, cweURL,
		))
	}

	sb.WriteString("*Opened automatically by ciotx. No code has been changed - this is a heads-up only.*")
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
