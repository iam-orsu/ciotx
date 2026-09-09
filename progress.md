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
| **Phase 2** | **Database-Backed License Management & CI/CD** | **READY TO START** | PostgreSQL, schema migrations, key generation, GitHub Actions |
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

## 5. Phase 2 Plan: Database-Backed License Management & CI/CD

### Goals
Transition from static single-key authorization (`MASTER_LICENSE_KEY`) to a scalable, relational database model supporting individual customer licenses, expiration dates, plan limits, and automated releases.

### Work Breakdown:

#### Task 2.1: PostgreSQL & Migration Infrastructure
* Add a `postgres:16-alpine` service to `docker-compose.yml` with encrypted credentials, persistent volumes, and health checks.
* Implement database connection pooling and migration runner in `server/internal/db/`.
* Write SQL schema migrations:
  * `001_create_licenses.sql`:
    ```sql
    CREATE TABLE licenses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        license_key VARCHAR(64) UNIQUE NOT NULL,
        organization VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        plan VARCHAR(32) NOT NULL DEFAULT 'starter', -- starter, pro, enterprise
        max_scans_per_month INT NOT NULL DEFAULT 50,
        scans_this_month INT NOT NULL DEFAULT 0,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX idx_licenses_key ON licenses(license_key);
    ```
  * `002_create_scans.sql`:
    ```sql
    CREATE TABLE scan_history (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        license_id UUID REFERENCES licenses(id) ON DELETE CASCADE,
        findings_count INT NOT NULL DEFAULT 0,
        critical_count INT NOT NULL DEFAULT 0,
        high_count INT NOT NULL DEFAULT 0,
        duration_ms BIGINT NOT NULL,
        client_version VARCHAR(32),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX idx_scan_history_license ON scan_history(license_id);
    ```

#### Task 2.2: License Management Handlers & CLI Admin Subcommands
* Refactor `server/handlers/auth.go` to query Postgres instead of just comparing against `MASTER_LICENSE_KEY` (keep master key as emergency backdoor/override).
* Implement Server CLI / Admin API to generate keys:
  ```bash
  ciotx-server license create --org "Acme Corp" --email "sec@acme.com" --plan pro --scans 500
  ciotx-server license revoke <key>
  ciotx-server license list
  ```

#### Task 2.3: GitHub Actions CI/CD Pipeline
* Create `.github/workflows/ci.yml`:
  * Runs on every PR / push to `main`.
  * Runs `go vet ./...`, `golangci-lint`, and unit tests for both `cli/` and `server/`.
* Create `.github/workflows/release.yml`:
  * Triggers on tag push (e.g. `v1.0.1`).
  * Cross-compiles binaries for all 5 platforms.
  * Creates GitHub Release with checksums (SHA256).
  * Automatically updates the `/releases/` distribution endpoint on the server.

#### Task 2.4: Integration Testing
* Write end-to-end integration tests (`server/tests/integration_test.go`):
  * Test license key validation (valid, expired, revoked, quota exceeded).
  * Test scan ingestion with mock LLM backend.
  * Test rate limiting and error response formatting.

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
