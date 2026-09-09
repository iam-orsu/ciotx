# ciotx — Project Progress & Roadmap

> **Document Purpose**: Single source of truth for project vision, completed work, architectural invariants, and future phases. If an AI agent or engineer loses context, this document enables immediate, seamless continuation without ambiguity or regression.

---

## 1. The Vision

**ciotx** is a closed-source, enterprise-grade SaaS source-code security auditor disguised as a lightweight developer CLI tool.

### Core Philosophy
* **Zero Friction**: Developers run `ciotx auth login`, enter their license key once, and run `ciotx scan .`. No flags, no config files, no complex setup.
* **Zero Noise, High Signal**: Traditional SAST tools drown developers in hundreds of false positives. ciotx utilizes an internal multi-phase reasoning pipeline (discovery, adversarial verification, and deep audit) to output only real, exploitable vulnerabilities with clear reproduction and remediation steps.
* **Invisible Intelligence**: The underlying LLM engine (DeepSeek) is entirely hidden from end users. The CLI contains **zero references** to any third-party AI provider or internal prompt architecture. To the user, ciotx is a proprietary, hyper-fast cloud vulnerability analysis engine.
* **Sustainable SaaS Model**: The operator hosts the backend and pays the upstream LLM API bills. End users purchase license keys with quota and feature entitlements.
* **Strict Privacy & Isolation**: Source code chunks are transferred over TLS, processed in memory during the audit pipeline, and never stored permanently on disk or used for training.
* **Turnkey Operator Experience**: An operator can bring up an entire production server on a fresh VPS in under 3 minutes with a single command: `sudo ./scripts/deploy.sh`.

---

## 2. Master Roadmap & Status

| Phase | Description | Status | Target / Notes |
|:---|:---|:---:|:---|
| **Phase 1** | **Core SaaS Infrastructure & Engine** | **COMPLETED (v1.0.0)** | Full CLI, Server, Nginx, Docker, deploy.sh, QA passed |
| **Phase 2** | **Database-Backed License Management & CI/CD** | **COMPLETED (v2.0.0)** | PostgreSQL, schema migrations, key generation, quota enforcement, admin CLI, GitHub Actions |
| **Phase 3** | **Usage Metering, Quotas & Rate Limits** | Planned | Tiered plans (Free/Pro/Enterprise), monthly quota enforcement |
| **Phase 4** | **Operator Admin Control Plane & Web Dashboard** | Planned | Web UI for key issuance, active scan metrics, revenue analytics |
| **Phase 5** | **Enterprise Scanners, Integrations & Distributed Queue** | Planned | Redis/Asynq workers, GitHub Actions scanner bot, Slack/Jira alerts |

---

## 3. Phase 1 Retrospective — What Was Built (COMPLETED)

### Overview
Phase 1 established the complete end-to-end working system: user CLI, hardened backend server, TLS reverse proxy, multi-stage LLM audit pipeline, cross-compilation pipeline, and one-touch deployment.

### Key Milestones Delivered:

#### A. CLI Tool (`cli/`)
* **Entry Point (`cmd/ciotx/main.go`)**:
  * `ciotx auth login`: Prompts for license key, validates against `/api/v1/auth/verify`, saves to `~/.ciotx/config.json`.
  * `ciotx scan <path>`: Local file ingestion, chunking, streaming upload to backend, interactive progress spinner, report generation.
  * `ciotx version`: Outputs CLI version and build metadata.
* **Code Ingestion (`pkg/scanner/ingest.go`)**:
  * Scans 13+ languages (Go, Python, JS/TS, Java, C/C++, Rust, PHP, C#, Solidity, SQL, Shell).
  * Automatically ignores binary files, test files, lock files, vendor dirs, `.git`, node_modules, and hidden files.
  * Enforces maximum file size (512 KB) and total codebase cap (25 MB) to avoid memory exhaustion.
  * Intelligent chunking with semantic boundaries.
* **Reporting Engine (`pkg/report/report.go`)**:
  * Produces both `ciotx-report.html` (rich, dark-mode, filterable executive dashboard) and `ciotx-report.json` (for CI/CD pipelines).
  * Zero hardcoded domains: dynamically uses compile-time injected URLs.
* **Compile-time Domain Injection (`pkg/api/client.go` & `pkg/config/config.go`)**:
  * `APIEndpoint` and `WebsiteURL` are compile-time ldflags (`-X ...`).
  * No user-editable or leakable domain settings in `~/.ciotx/config.json`.
  * Sends descriptive `User-Agent: ciotx-cli/<version> (<os>/<arch>)`.

#### B. Backend Server (`server/`)
* **Core Daemon (`server/main.go`)**:
  * Graceful SIGTERM/SIGINT shutdown with a 60-second drain window.
  * Enforced HTTP timeouts: `ReadTimeout: 5m`, `WriteTimeout: 35m` (matches client timeout), `IdleTimeout: 120s`.
  * Startup validation ensuring critical environment variables (`LLM_API_KEY`, `MASTER_LICENSE_KEY`) are present.
* **Security & Middleware (`server/handlers/`)**:
  * `auth.go`: Constant-time license key validation (`crypto/subtle.ConstantTimeCompare`) with fail-secure defaults.
  * `middleware.go`: Panic recovery handler (prevents server crashes) and unique `X-Request-ID` tracing.
* **Audit Pipeline (`server/internal/llm/`)**:
  * Three-tier reasoning engine:
    1. **Discovery (`discovery.go`)**: High-level AST/vulnerability sweep across code chunks using reasoning models.
    2. **Adversarial Verification**: Verification phase that ruthlessly filters out false positives, hallucinations, and theoretical vulnerabilities.
    3. **Deep Audit (`audit.go`)**: Structured JSON synthesis providing CVSS score, CWE ID, file location, proof of concept, and concrete remediation code.
  * **Resilient Context-Aware HTTP Client (`client.go`)**:
    * Full context cancellation propagation (`scanCtx` with 30m timeout passed from HTTP handler down to every outbound LLM request).
    * Exponential backoff retry with jitter that respects `ctx.Done()`.

#### C. Production Infrastructure & Operations
* **Nginx (`nginx/`)**:
  * Production TLS reverse proxy based on `nginx:1.27-alpine`.
  * Rate-limiting zone: `10 requests/minute` with burst capacity to prevent abuse.
  * Serves built binaries from `/releases/` directory with automatic indexing.
  * `client_max_body_size: 64m` to handle large codebase uploads.
* **Docker Compose (`docker-compose.yml`)**:
  * Multi-container setup (`server`, `nginx`, `certbot`).
  * Hard memory and CPU resource limits on containers (`server`: 1GB RAM / 1.5 CPUs, `nginx`: 256MB RAM / 0.5 CPUs).
  * `stop_grace_period: 65s` to allow in-flight scans to complete before container termination.
  * Pinned non-root users and alpine base images for minimal attack surface.
* **Zero-Touch Deployment (`scripts/deploy.sh`)**:
  * Validates `.env` and checks DNS A records against VPS public IP.
  * Automatically installs Docker & Docker Compose if missing.
  * Obtains Let's Encrypt SSL certificates automatically.
  * Cross-compiles CLI binaries for 5 target platforms:
    - `linux/amd64`
    - `linux/arm64`
    - `darwin/amd64`
    - `darwin/arm64`
    - `windows/amd64`
  * Injects `DOMAIN_NAME` into binaries via `-ldflags`.
  * Auto-generates `scripts/install.sh` pointing to the operator's actual domain.
  * Launches the stack and performs an automated health check against `https://${DOMAIN_NAME}/health`.

---

## 4. Architectural Invariants (DO NOT VIOLATE)

Any future code changes or agent interactions must strictly follow these rules:

1. **Zero Provider Mentions**: Never mention DeepSeek, OpenAI, Anthropic, or any LLM vendor in CLI code, client-facing error messages, or API responses. Use generic terms: "ciotx cloud engine", "deep analysis", "security auditor".
2. **Compile-Time Domain Injection**: Never hardcode domains (e.g. `api.ciotx.ai`) in Go code. The single source of truth is `DOMAIN_NAME` in `.env`, passed at compile time via `-ldflags`:
   ```bash
   -ldflags="-X 'ciotx/cli/pkg/config.APIEndpoint=https://${DOMAIN_NAME}' -X 'ciotx/cli/pkg/config.WebsiteURL=https://${DOMAIN_NAME}' -X 'ciotx/cli/pkg/config.Version=${VERSION}'"
   ```
3. **No Domain in User Config**: `~/.ciotx/config.json` should ONLY store `{"license_key": "..."}`. Never allow users to change the API endpoint via config file (prevents MITM/tampering).
4. **Context Propagation**: Every database, network, and LLM call must accept a `context.Context` and honor its cancellation.
5. **Fail-Secure Security**: Missing master keys, database disconnection, or invalid input must always default to denying access, never allowing unauthenticated requests.
6. **Timeouts Synchronization**: Client HTTP timeout (35m) must align with Server `WriteTimeout` (35m) and `scanCtx` limit (30m).

---

## 4.5. Post-Phase-1 Quality Pass (v1.0.1) — COMPLETED

A focused quality pass was applied after Phase 1 to close the gaps identified in a Phase 1 review. No new features were added — all changes are correctness, quality, and test coverage improvements.

### Issues Fixed

#### A. Variable Shadowing — `server/internal/llm/audit.go`
- **Problem**: `ctx := ""` on line 58 shadowed the outer `ctx context.Context` function parameter. If Go tooling or a future refactor relied on `ctx` inside that block, it would silently use the string instead of the context.
- **Fix**: Renamed the local string variable to `surroundingCode` throughout the block.

#### B. Duplicate `max`/`min` helpers (Go 1.21 builtins)
- **Problem**: Custom `max(a, b int)` and `min(a, b int)` functions were copy-pasted into four separate files: `server/handlers/scan.go`, `server/internal/llm/audit.go`, `server/internal/llm/client.go`, and `cli/pkg/scanner/ingest.go`.
- **Fix**: Removed all four custom definitions. Both modules require `go 1.21`, which ships `min` and `max` as generic builtins — all call sites work identically.

#### C. `EstimatedCostUSD` Always Zero
- **Problem**: The `estimated_cost_usd` field was present in the API response but was always `0.0`. Token usage was tracked but never converted to dollars.
- **Fix**:
  - Added `CostUSD(u Usage, model string) float64` function to `server/internal/llm/client.go` with DeepSeek's published per-model pricing (deepseek-reasoner and deepseek-chat rates, cache-hit vs. cache-miss differentiated).
  - Separated combined `usage` into `discoveryUsage` and `auditUsage` in `ScanHandler` so each model's tokens are priced at the correct rate.
  - `EstimatedCostUSD` in `ScanResponse.Stats` is now populated with the real computed value.

#### D. 25MB Total Codebase Cap Not Enforced
- **Problem**: `progress.md` and the Phase 1 description documented a 25MB total codebase cap, but `cli/pkg/scanner/ingest.go` only enforced a 512KB per-file limit. A repo with thousands of small files could exceed 25MB and cause memory exhaustion.
- **Fix**: Added `maxCodebaseBytes = 25 * 1024 * 1024` constant and a running `totalBytes` counter in `IngestCodebase`. When the next file would push the total over 25MB, the walk returns `filepath.SkipAll` to stop cleanly. Named constants `maxFileBytes` and `maxCodebaseBytes` replace the inline magic numbers.

#### E. Zero Tests — Now Fixed
- **Problem**: No test files existed anywhere in the project.
- **Fix**: Added 4 test files with 25 test cases total covering the core logic:

  | File | What it tests |
  |:---|:---|
  | `server/internal/llm/discovery_test.go` | `parseFindings` (wrapped JSON, code fences, empty, garbage, Windows paths), `normalizeSeverity` (all variants) |
  | `server/internal/llm/client_test.go` | `CostUSD` for discovery model, audit model, and zero usage |
  | `server/handlers/scan_test.go` | `verifyFindings` (good finding, hallucinated file, empty evidence, line correction, deduplication), `extractFilesContent` (basic, multi-file, multi-chunk) |
  | `cli/pkg/scanner/ingest_test.go` | `FormatNumberedFile`, `PartitionChunks` (single/multi/empty), `IngestCodebase` (basic, ignored dirs, large file skip, binary skip) |
  | `cli/pkg/report/report_test.go` | `WriteJSON` (round-trip, empty), `WriteHTML` (valid HTML, XSS escaping, empty state, severity sorting) |

  All tests pass: `go test ./...` — green across both `server/` and `cli/` modules.

### Architectural Invariants Added
- `CostUSD` is the single source of truth for token cost calculation. Per-model pricing is in named constants in `client.go` alongside a source URL comment.
- Discovery and audit usages **must** be tracked separately in `ScanHandler` to preserve per-model pricing accuracy.

---

## 5. Phase 2 — Database-Backed License Management & CI/CD (COMPLETED v2.0.0)

### What Was Built

#### A. PostgreSQL Database (`server/internal/db/`)

**`db.go`** — Connection pool using `pgx/v5/pgxpool`:
- `Init(ctx)`: opens pool (max 10 / min 2 conns), pings before accepting traffic
- `Pool()`: returns the active pool; panics if Init not called (fail-fast, not silent nil deref)
- `Close()`: drains pool on graceful shutdown
- Reads `DATABASE_URL` (preferred) or individual `POSTGRES_*` env vars
- DB failure is non-fatal at startup — master key fallback still works for local dev

**`migrate.go`** — Embedded migration runner:
- SQL files embedded via `//go:embed migrations/*.sql`
- Applied in lexicographic order, tracked in `schema_migrations` table
- Idempotent — already-applied migrations are skipped on restart
- Run automatically at server startup before accepting requests

**`license.go`** — License CRUD:
- `GetLicenseByKey`: single query; returns `pgx.ErrNoRows` if not found (not a generic error)
- `IncrementScanCount`: atomic SQL UPDATE that also resets `scan_month` if the calendar month changed — no background job needed
- `RecordScan`: writes to `scan_history` after each completed scan
- `CreateLicense`: generates `ciotx_<48-hex-chars>` key, inserts into DB
- `RevokeLicense`: sets `is_active = FALSE` (preserves history)
- `ListLicenses`: returns all licenses newest-first

**SQL Migrations:**
- `001_create_licenses.sql`: `licenses` table with `scan_month VARCHAR(7)` for lazy monthly quota reset
- `002_create_scan_history.sql`: `scan_history` table with foreign key and time indexes

#### B. Updated Auth Handler (`server/handlers/auth.go`)

`resolveKey` two-step lookup:
1. DB lookup via `db.GetLicenseByKey` — enforces `is_active`, `IsExpired()`
2. Master key fallback via `crypto/subtle.ConstantTimeCompare` — returns `nil` license (admin bypass, no quota)

Auth middleware now attaches the `*db.License` to the request context via `context.WithValue` so the scan handler can access it without a second DB round-trip.

`AuthVerifyHandler` now returns `plan` and `organization` in the response so the CLI can display plan info after login.

#### C. Quota Enforcement (`server/handlers/scan.go`)

`ScanHandler` now:
1. Reads license from context before any work
2. If DB-backed license: checks `IsQuotaExceeded()` → returns HTTP 402 with clear message
3. Runs scan pipeline (unchanged)
4. After response sent: background goroutine increments scan counter and writes scan history row
5. Master key auth: bypasses quota entirely

Monthly quota reset is lazy: `IncrementScanCount` SQL checks `scan_month != current_month` and resets to 1 if so. No cron job, no race condition.

#### D. Admin CLI (`server/admin/license.go`)

The server binary is now dual-purpose. When called with `license` as first arg, runs admin commands instead of starting the server:

```bash
# Issue a new key
docker compose exec api /ciotx-server license create \
  --org "Acme Corp" --email sec@acme.com --plan pro --scans 500 --expires 365

# Revoke a key
docker compose exec api /ciotx-server license revoke ciotx_abc123...

# List all licenses (tabular output)
docker compose exec api /ciotx-server license list
```

#### E. Docker & Environment

`docker-compose.yml` additions:
- `postgres:16-alpine` service with persistent named volume, health check, resource limits
- `api` service now depends on `postgres` health check before starting
- `POSTGRES_*` env vars passed to api container

`.env.example` updated with `POSTGRES_PASSWORD` (required, must be strong).

`deploy.sh` updated:
- `POSTGRES_PASSWORD` added to required vars validation
- Warns if password is shorter than 16 chars
- Prints license management commands in post-deploy summary

#### F. GitHub Actions

**`ci.yml`** — runs on every push/PR to `main`:
- Spins up a real `postgres:16-alpine` service container for integration-ready tests
- `go vet ./...` on both modules
- `go test ./... -race -timeout 120s` on both modules
- Separate build smoke-test job (compiles server + CLI linux/amd64)

**`release.yml`** — runs on `v*.*.*` tag push:
- Cross-compiles CLI for all 5 platforms
- Generates `checksums.txt` (SHA256)
- Creates GitHub Release via `softprops/action-gh-release@v2` with all binaries attached

### Architectural Invariants Added (Phase 2)

1. **DB is non-fatal at startup**: server starts even if Postgres is unreachable. Master key still works. This prevents a DB blip from taking down the entire service.
2. **Quota check is pre-scan**: rejection happens before any LLM tokens are spent. HTTP 402 is the correct status code — the CLI already handles it with "scan limit reached — upgrade your plan".
3. **Post-scan accounting is fire-and-forget**: scan history write happens in a background goroutine after the HTTP response is flushed. A failed write logs a warning but never fails a scan.
4. **Monthly reset is lazy SQL**: no background job or cron needed. The `scan_month` column is the single source of truth.
5. **Admin CLI uses same binary**: `ciotx-server license ...` — no separate admin binary to build, deploy, or secure.

---

## 5.5. Post-Phase-2 Deep QA Audit (v2.0.1) — COMPLETED

A comprehensive security and correctness audit was performed across all files in both modules and the infrastructure layer. All issues were fixed in a single pass.

### Issues Fixed

#### A. CRITICAL — DB Pool Nil Panic Breaks Master Key Fallback (`server/internal/db/`)
- **Problem**: `main.go` allows DB init to fail non-fatally so the master key still works when Postgres is unreachable. But `license.go` called `Pool()` directly, which panics on nil. The panic was caught by `RecoveryMiddleware` returning HTTP 500 — the master key fallback in `resolveKey` was **never reached**. Master key was effectively broken when DB was down.
- **Fix**: Added `IsAvailable() bool { return pool != nil }` to `db.go`. Every function in `license.go` now guards with `if !IsAvailable() { return ..., fmt.Errorf("database unavailable") }` before calling `Pool()`. `GetLicenseByKey` specifically returns `pgx.ErrNoRows` when DB is unavailable, causing `resolveKey` to naturally fall through to the master key check.

#### B. CRITICAL — DSN Password Injection via Special Characters (`server/internal/db/db.go`)
- **Problem**: `buildDSN()` used `fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", ...)`. A `POSTGRES_PASSWORD` containing spaces, `=`, or `'` would corrupt the DSN string, cause pgx to fail parsing, and potentially leak the password in error logs.
- **Fix**: Replaced `fmt.Sprintf` with `url.URL{Scheme: "postgres", User: url.UserPassword(user, password), Host: net.JoinHostPort(host, port), ...}` — Go's `net/url` package handles all special-character escaping correctly.

#### C. CRITICAL — LLM Response Body Unbounded (`server/internal/llm/client.go`)
- **Problem**: `io.ReadAll(resp.Body)` in `doRequest` had no size limit. A malicious or misbehaving LLM provider could send gigabytes, exhausting server memory.
- **Fix**: Capped to `io.LimitReader(resp.Body, 10<<20)` (10 MB). LLM responses are JSON and never legitimately exceed a few hundred KB.

#### D. CRITICAL — Migration Not in Transaction (`server/internal/db/migrate.go`)
- **Problem**: Each migration applied its SQL and then wrote to `schema_migrations` as two separate `pool.Exec` calls. A crash between the two would leave the DB in an inconsistent state: migration applied but not recorded → startup would re-apply it and fail with "already exists".
- **Fix**: Wrapped both `Exec` calls (migration SQL + `schema_migrations` INSERT) in a single `pool.Begin` / `tx.Commit` transaction. Rollback on any error ensures atomicity.

#### E. Regex Compiled Per-Request (`server/handlers/scan.go`)
- **Problem**: `extractFilesContent` called `regexp.MustCompile` twice on every HTTP scan request — unnecessary CPU overhead and GC pressure.
- **Fix**: Moved both regexes to package-level `var` declarations compiled once at process start.

#### F. SECURITY — No Plan Validation in Admin CLI (`server/admin/license.go`)
- **Problem**: `--plan` accepted any string, allowing arbitrary values like `"free"`, `"god"`, or `""` to be stored in the DB.
- **Fix**: Added `validPlans` map (`starter|pro|enterprise`) and validation before calling `db.CreateLicense`.

#### G. SECURITY — No Email Validation in Admin CLI (`server/admin/license.go`)
- **Problem**: `--email` accepted any string including empty (covered by nil check but not format).
- **Fix**: Basic `strings.Contains(*email, "@")` check with clear error message.

#### H. SECURITY — License Key Length Not Validated Before DB Query (`server/handlers/auth.go`)
- **Problem**: `resolveKey` sent arbitrarily long strings to the DB without a length cap — potential for oversized queries.
- **Fix**: Added `if len(key) > 128 { return nil, fmt.Errorf("key too long") }` check before any DB or comparison operation.

#### I. SECURITY — CLI Scan Response Body Unbounded (`cli/pkg/api/client.go`)
- **Problem**: `io.ReadAll(resp.Body)` in `Scan()` had no size limit — a malicious or misbehaving server could send a very large payload causing the CLI to OOM.
- **Fix**: Capped to `io.LimitReader(resp.Body, 5<<20)` (5 MB). Scan responses are JSON findings and never legitimately exceed a few hundred KB.

#### J. deploy.sh Step Header Typo
- **Problem**: Step 5 (build & deploy) was labeled "Step 4" (duplicate of the CLI build step header above it).
- **Fix**: Changed to "Step 5 — Building & Deploying".

### Verification
- `go build ./...` passes cleanly for both `server/` and `cli/` modules after all changes.
- All existing tests still pass.

---

## 6. Phase 3 & Beyond: Future Architecture

### Phase 3: Usage Metering, Quotas & Alerting
* Automatic monthly quota resets via cron / background worker.
* Webhook notifications (Slack / Microsoft Teams) when critical vulnerabilities are found.
* Rate limiting per license key (in addition to IP-based rate limiting in Nginx).

### Phase 4: Operator Admin Web Control Plane
* Single-page dashboard (Go embedded template or lightweight SPA) on `https://${DOMAIN_NAME}/admin`.
* View active scans, recent audits, system health, LLM token spend, and revenue estimates.
* One-click license creation and instant revocation.

### Phase 5: Distributed Workers & AST Pre-filtering
* Asynchronous scan architecture: For codebases > 25MB, switch to job queue (`asynq` + Redis) with polling or SSE progress reporting.
* Local Tree-sitter / AST parsing before cloud transmission to strip comments, dead code, and focus analysis only on risk surfaces (reducing LLM token costs by ~40%).

---

## 7. Developer Quick Reference

### Local Development
```bash
# Build CLI locally
make build

# Cross-compile for all 5 platforms
make build-all

# Run code linters & static checks
make vet

# Run tests
make test
```

### Production Deployment
```bash
# Edit .env with production credentials
cp .env.example .env
nano .env

# Deploy or upgrade the full stack
sudo ./scripts/deploy.sh
```

### Git Workflow
* Main branch: `main`
* Commit convention: Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`)
* Line endings: Always LF (enforced by `.gitattributes`)
