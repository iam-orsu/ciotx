# ciotx — AI Security Auditor

> Find real, exploitable vulnerabilities in your codebase before attackers do.

[![CI](https://github.com/iam-orsu/ciotx/actions/workflows/ci.yml/badge.svg)](https://github.com/iam-orsu/ciotx/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/iam-orsu/ciotx)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21%2B-blue)](https://go.dev)

---

ciotx is a command-line security scanner that sends your source code through a multi-stage AI analysis pipeline — discovery, evidence verification, and adversarial audit — and returns only confirmed, exploitable vulnerabilities with exact file locations, line numbers, code evidence, and remediation guidance.

It is designed to be self-hosted. You run the server, you own the data, and your users' code never touches any third-party service directly.

---

## For Users

### Install

```bash
curl -fsSL https://api.ciotx.ai/install.sh | sh
```

### Authenticate

```bash
ciotx auth login
# Enter your license key when prompted
```

### Scan

```bash
# Scan your current directory
ciotx scan .

# Scan a specific path
ciotx scan /path/to/your/project
```

After the scan, two files appear in your current directory:

- **`ciotx-report.html`** — Open in a browser. Interactive report with filter by severity, search by file, collapsible finding cards with code evidence and remediation steps.
- **`ciotx-report.json`** — Machine-readable findings for CI/CD pipelines and custom tooling.

### Other Commands

```bash
ciotx status           # View your plan and monthly scan usage
ciotx history          # Last 10 scans with finding counts and durations
ciotx history --limit 20
```

---

## How It Works

ciotx runs a three-pass pipeline on the server side. Your machine never calls any AI provider directly.

```
Your machine                    ciotx server
────────────                    ────────────────────────────────
1. Reads your source files      Receives code chunks over HTTPS
   (never reads .env, secrets)
                                2. Discovery pass
                                   Deep reasoning model scans every file
                                   for exploitable vulnerabilities

                                3. Evidence verification
                                   Each finding is anchored back to the
                                   actual source — hallucinations are dropped

                                4. Adversarial audit
                                   A skeptical second model challenges each
                                   finding and rejects false positives

                                Returns only confirmed findings
5. Generates HTML + JSON report
```

**What gets sent:** only source code files. Secrets, `.env` files, lock files, binaries, and files over 512 KB are excluded automatically.

**What comes back:** a list of confirmed findings. Each has a severity level (Critical / High / Medium / Low), a CWE identifier, the exact file and line numbers, the vulnerable code as evidence, a description of the attack vector, and remediation guidance.

---

## Supported Languages

Go · Python · JavaScript · TypeScript · Java · Kotlin · C# · C · C++ · PHP · Ruby · Rust · Swift · Scala · Solidity · SQL · Shell · Bash · YAML · Terraform · Dockerfile

---

## What ciotx Finds

- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Cross-Site Scripting — Reflected, Stored, DOM (CWE-79)
- Insecure Deserialization (CWE-502)
- Path Traversal (CWE-22)
- Server-Side Request Forgery (CWE-918)
- Hardcoded Credentials (CWE-798)
- Cryptographic weaknesses — broken algorithms, insecure random, weak keys
- Authentication and authorization bypass
- Race conditions and TOCTOU vulnerabilities
- Memory safety issues (buffer overflow, use-after-free, null dereference)
- Business logic vulnerabilities
- Insecure direct object references (CWE-639)
- XML External Entity injection (CWE-611)
- Open redirect (CWE-601)

---

## For Operators (Self-Hosting)

ciotx is designed to be run as a SaaS product on your own infrastructure. You deploy the server, issue license keys to your customers, and keep 100% of the revenue.

### What You Get

- **Full API server** — handles auth, scanning, rate limiting, quotas
- **Admin dashboard** — issue/revoke license keys, view usage metrics, monitor scans
- **CLI binary builder** — your domain is compiled into every CLI binary
- **One-line installer** — `curl https://yourdomain.com/install.sh | sh`
- **GitHub App integration** — automatically scans every push, opens fix PRs
- **Automatic TLS** — Let's Encrypt via certbot
- **Zero vendor lock-in** — you own the server, the database, the API keys

### Quick Deploy

```bash
# On a fresh Ubuntu VPS (2 GB RAM minimum, domain pointing to VPS IP)
git clone https://github.com/iam-orsu/ciotx.git
cd ciotx
cp .env.example .env
nano .env   # fill in your domain, DeepSeek API key, passwords
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh
```

The script installs Docker, gets a TLS certificate, builds everything, and starts the stack. Takes 5–10 minutes on a fresh VPS.

**→ See [DEPLOY.md](DEPLOY.md) for the complete step-by-step deployment guide**, including how to get your DeepSeek API key, set up DNS, issue license keys, test a scan end-to-end, set up GitHub App integration, and troubleshoot common problems.

### Architecture

```
Internet
   │
   ▼
nginx (TLS, rate limiting, static files)
   │
   ▼
Go API server
   ├── /v1/scan       — runs discovery + audit pipeline
   ├── /v1/auth/...   — license key verification
   ├── /v1/status     — plan and quota info
   ├── /v1/history    — scan history
   ├── /admin         — operator dashboard (HMAC session cookie)
   └── /webhooks/github — GitHub App push events
   │
   ├── PostgreSQL — licenses, scan history, GitHub jobs
   └── DeepSeek API — internal, never exposed to users
```

### License Plans

You define plans however you like. The three built-in tiers are:

| Plan | Typical use |
|:-----|:------------|
| `starter` | Individual developers, up to 50 scans/month |
| `pro` | Small teams, up to 500 scans/month |
| `enterprise` | Large organizations, custom scan limits |

Scan limits reset at the start of each calendar month. Limits are enforced server-side — no client-side check, no bypass.

### Environment Variables

| Variable | Required | Description |
|:---------|:---------|:------------|
| `DOMAIN_NAME` | Yes | Your domain (e.g. `api.yourdomain.com`) — baked into every CLI binary |
| `VPS_SERVER_IP` | Yes | Your server's public IP — used for DNS verification |
| `SSL_EMAIL` | Yes | Email for Let's Encrypt certificate registration and renewal alerts |
| `LLM_API_KEY` | Yes | DeepSeek API key — internal to server, never exposed to users |
| `MASTER_LICENSE_KEY` | Yes | Operator bypass key for testing and emergency access |
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password — use `openssl rand -hex 32` |
| `ADMIN_PASSWORD` | No | Password for `/admin` dashboard — leave empty to disable |
| `GITHUB_APP_ID` | No | GitHub App ID — enables push-triggered scanning and fix PRs |
| `GITHUB_APP_PRIVATE_KEY_BASE64` | No | Base64-encoded GitHub App private key |
| `GITHUB_WEBHOOK_SECRET` | No | GitHub webhook HMAC secret |

---

## Project Structure

```
ciotx/
├── cli/                    — User-facing CLI binary
│   ├── cmd/ciotx/          — Entry point (main.go)
│   └── pkg/
│       ├── api/            — Backend API client
│       ├── config/         — License key storage (~/.ciotx/config.json)
│       ├── report/         — HTML + JSON report generation
│       ├── scanner/        — File ingestion and chunking
│       └── types/          — Shared finding type definitions
│
├── server/                 — Backend API server (runs in Docker)
│   ├── main.go             — HTTP server + admin CLI dispatch
│   ├── handlers/           — HTTP request handlers
│   │   ├── scan.go         — Main scan pipeline handler
│   │   ├── auth.go         — License key authentication
│   │   ├── admin.go        — Admin dashboard handlers
│   │   ├── webhook.go      — GitHub App webhook handler
│   │   ├── status.go       — Account status handler
│   │   ├── history.go      — Scan history handler
│   │   └── middleware.go   — Recovery + request logging middleware
│   ├── internal/
│   │   ├── db/             — PostgreSQL pool, migrations, queries
│   │   ├── github/         — GitHub App auth + API client
│   │   ├── llm/            — Internal AI provider client (hidden from users)
│   │   ├── ratelimit/      — Per-key concurrency limiter
│   │   └── types/          — Server-side finding types
│   └── worker/             — Background GitHub scan job processor
│
├── nginx/                  — Reverse proxy (TLS, rate limiting)
│   ├── nginx.conf.template — Config with DOMAIN_NAME substitution
│   ├── docker-entrypoint.sh
│   └── Dockerfile
│
├── scripts/
│   ├── deploy.sh           — One-command full deployment
│   └── install.sh          — Generated per-deployment CLI installer
│
├── docker-compose.yml      — Full production stack
├── .env.example            — Configuration template
├── DEPLOY.md               — Complete deployment guide
└── .github/workflows/ci.yml — CI: vet + test + build smoke test
```

---

## Security Architecture

- **Zero third-party branding leaks** — AI provider names, model names, and API endpoints are constants inside the server binary. They never appear in logs, error messages, API responses, or the CLI.
- **Config file stores only the license key** — `~/.ciotx/config.json` contains `{"license_key": "..."}` and nothing else. Users cannot change the API endpoint.
- **Fail-secure** — if the database is unavailable, the master key fallback still works. If the master key is missing, the server refuses to start.
- **Context propagation** — every database query, LLM call, and outbound HTTP request accepts a `context.Context` and honours cancellation and timeouts.
- **HMAC-signed session cookies** — admin sessions use a 32-byte random key generated fresh on each server start. Restarting the server invalidates all existing admin sessions.
- **Per-IP login rate limiting** — 5 failed admin login attempts triggers a 15-minute lockout. Rate limiter uses `X-Real-IP` (set by nginx to `$remote_addr`) to prevent spoofing.
- **Non-root containers** — all Docker containers run as non-root users.
- **Internal Docker network** — PostgreSQL is only reachable within the container network, never from the internet.

---

## Contributing

Issues and PRs are welcome. Please open an issue before starting large changes.

Run tests:
```bash
cd server && go test ./...
cd cli && go test ./...
```

---

## License

MIT — see [LICENSE](LICENSE)
