# PatchGuard

PatchGuard scans C/C++ firmware projects and source files, reports evidence-backed memory-safety findings, and helps developers review repair proposals.

## Run locally

Requirements: Docker Desktop or Docker Engine with Compose, plus a Supabase project.

1. Run [`supabase/migrations/202610310001_patchguard_jobs.sql`](supabase/migrations/202610310001_patchguard_jobs.sql) in the Supabase SQL Editor. The migration creates the `patchguard_backend` role before granting its table access.
2. In the SQL Editor, enable its login and set a strong password: `ALTER ROLE patchguard_backend LOGIN PASSWORD 'use-a-long-random-secret';` Replace the example password with your own.
3. Copy `.env.example` to `.env` and set `SUPABASE_DB_URL` to the Supabase session-pooler connection string (port 5432). For the shared pooler, use `patchguard_backend.<project-ref>` as the username. Keep `sslmode=require` and URL-encode special characters in the password. Use the database connection string from **Connect**, not the Supabase project URL or anon key. The direct `db.<project-ref>.supabase.co` endpoint is IPv6-only unless the project has the IPv4 add-on; use the session pooler on IPv4-only Docker hosts.
4. Start the app:

```powershell
Copy-Item .env.example .env
# Edit .env and set SUPABASE_DB_URL before starting.
docker compose up --build
```

Set `AUTH_SECRET` to a random value of at least 32 characters, `REPAIR_INTERNAL_SECRET` to a separate long random value, and set `SUPABASE_URL` plus the project's publishable key in `SUPABASE_PUBLISHABLE_KEY`. `FRONTEND_URL` defaults to `http://localhost:8000`; add `http://localhost:8000/auth/callback` to Supabase Auth's allowed redirect URLs. Open <http://localhost:8000>, create an account, then upload C/C++ files, a complete folder, or a ZIP project. Supabase Auth handles passwords; its confirmation link returns to the callback on port 8000, which validates the session and sets the PatchGuard cookie. Folder uploads retain supported source and text project files while omitting generated directories. The web container publishes this port on the host-facing `edge` network and reaches the API over the private `inside` network. The API itself is not published directly. The worker runs Clang Static Analyzer, Cppcheck, and Semgrep as a non-root user. Build/test subprocesses have no network access. Model keys stay on the API service and are never sent to the browser or worker.

### Demo sign-in

Create a dedicated demo user in Supabase Auth, confirm its email, then set `DEMO_EMAIL` and `DEMO_PASSWORD` in `.env`. Restart the API with `docker compose up -d --force-recreate api`. The sign-in page shows a **Try demo** button only when both values are configured. Credentials stay on the API and the button signs in through Supabase Auth. Keep the demo account separate from real user data; the demo view starts empty unless you add demo-owned scans.

### GitHub sign-in

The login page redirects to Supabase Auth's GitHub provider and returns to `http://localhost:8000/auth/callback?source=github`. In GitHub, create an OAuth App with homepage `http://localhost:8000` and authorization callback `https://<project-ref>.supabase.co/auth/v1/callback`. In Supabase Authentication → Sign In / Providers, enable GitHub and enter that app's client ID and secret. Add both `http://localhost:8000/auth/callback` and `http://localhost:8000/auth/callback?source=github` to Supabase Authentication → URL Configuration → Redirect URLs. The OAuth client secret belongs in Supabase, not PatchGuard `.env`.

After GitHub sign-in, choose one of the account's public repositories to scan its default branch. PatchGuard requests no repository write scope. It uses the provider token for repository-list and metadata requests, keeps it in page memory during this flow, and does not save it in the session cookie or scan job. The public archive download does not include the token. The imported source snapshot records its branch and commit SHA. This MVP does not access private repositories or create pull requests.

Supabase Postgres stores job metadata and acts as the durable queue. The worker claims pending rows with `FOR UPDATE SKIP LOCKED`; no Redis service or Redis socket is used. Source archives and repair proposals remain in the one-hour local `jobs` volume and are removed by worker cleanup.

The worker defaults to `ANALYSIS_MODE=legacy`, which preserves the current scanner response. To inspect the additive IR pipeline, set `ANALYSIS_MODE=shadow` in `.env`; this intentionally runs the analyzers a second time and stores comparison data separately. `ANALYSIS_MODE=unified` opts into IR-normalized findings mapped back to the existing response shape. See [the analysis architecture](docs/ANALYSIS_ARCHITECTURE.md).

### Supabase connection troubleshooting

If worker logs report `Network is unreachable` for a `2a05:...` address, the configured direct database hostname resolved to IPv6 but the Docker network has no IPv6 route. In Supabase **Connect**, copy the **Session pooler** string (port `5432`) into `SUPABASE_DB_URL`; for the shared pooler, use `patchguard_backend.<project-ref>` as the username. Keep `sslmode=require`, then recreate the stack with `docker compose down --remove-orphans` and `docker compose up --build`. The worker backs off between connection retries and logs this fix as a hint.

### Repair providers

For Groq repairs, set `GROQ_API_KEY` and optionally `GROQ_MODEL`. The automatic provider tries Ollama and falls back to Groq; scan details report which one generated a proposal. If fallback is used, relevant source is sent to Groq. The legacy OpenAI-compatible hosted provider remains supported by the API but is not shown in the UI.

After a standard repair fails, **Deep repair** is available while attempts remain. It sends the bounded source context and prior check results to Groq only after the user confirms, uses `GROQ_DEEP_MODEL` (default `openai/gpt-oss-120b`) with high reasoning effort, then runs the same edit validation and isolated verification. Scan-only jobs can request Deep repair directly. `REPAIR_INTERNAL_SECRET` must be set to a long random value in `.env`; the worker uses it to ask the private API service to generate proposals, so provider credentials remain only in the API container.

Start Ollama and run `ollama pull qwen2.5:3b` if the model is missing. For Ollama, set `OLLAMA_BASE_URL` and `OLLAMA_MODEL`; the API service must be able to reach that Ollama endpoint. The default model is `qwen2.5:3b`. The API uses LangChain's Ollama chat integration with schema-constrained proposals. Repairs use bounded source context up to `MAX_REPAIR_CONTEXT_CHARS` (24,000 characters by default) and exact-match edits; the source file itself may be larger. Proposals are limited by `MAX_REPAIR_CHANGED_LINES` and are rechecked against a source hash before application. Context size is a character limit, not an exact token count.

Without model configuration, scanning and reports still work; repair generation explains how to configure a provider.

## Deployment

Run the Compose stack on a Linux VM behind HTTPS termination (for example, a reverse proxy managed by the operator). Set `AUTH_COOKIE_SECURE=true` when HTTPS is enabled. Supabase Auth manages email/password credentials; PatchGuard issues short-lived signed HTTP-only session cookies and scopes jobs to the Auth user ID. Basic upload/login rate limits are process-local. The MVP enforces upload, file-count, extracted-size, CPU-time, and wall-clock limits; the analysis worker runs as an unprivileged user and its build/test subprocesses run without network access in bubblewrap. The worker needs egress to Supabase Postgres for queue and job state. Restrict VM egress to the Supabase endpoint where the host firewall supports it. Do not mount Docker sockets or model-provider credentials into the worker.

Uploaded projects and generated artifacts are stored in the `jobs` volume and expire after one hour. Job state and queue rows use the existing `patchguard_jobs` table; account credentials remain in Supabase Auth. Session cookies expire after eight hours. Email confirmation follows Supabase project settings; password reset, multi-factor authentication, shared rate limiting, and external secrets management are not implemented.

## Supported MVP checks

- C/C++ scans: Clang Static Analyzer and Cppcheck report CWE-476 diagnostics; custom Semgrep rules report risky buffer operations as candidates and map CWE-120/121/122 only from available destination context. Analyzer failures are reported as partial or failed scans.
- Repairs: automatic Ollama → Groq fallback, manual Ollama or Groq, opt-in Deep repair, and legacy hosted OpenAI-compatible chat-completions API; proposals are size- and change-bounded, applied only to a copy, then independently rescanned. Acceptance records the signed-in author's review and verification outcome. Proposals created before source hashes were stored must be regenerated. A job with an existing patched copy requires a new scan for another repair.
- Evidence: build and test checks are attempted only for detected CMake/CTest or Make projects. AddressSanitizer/UndefinedBehaviorSanitizer checks are attempted for CMake projects with tests. Security and overall verification report passed, failed, or unverified; unavailable checks are never passes. Performance comparison is opt-in through a project benchmark manifest.
- Exports: patch ZIP and SARIF 2.1.0.

### Optional benchmark

Add `.patchguard/benchmark.json` to request a baseline-versus-patch timing comparison:

```json
{"command": ["/build/firmware_benchmark", "--quick"], "runs": 3}
```

The command runs without a shell, with no network, and only inside the build sandbox. PatchGuard reports median timings and the relative delta; it does not turn noisy measurements into a performance pass/fail claim.

This is a triage and repair assistant, not a complete CWE scanner or a guarantee of zero-day detection, functional equivalence, or absence of performance regressions.

## CWE data

The application bundles a reviewed CWE 5.0 catalog snapshot for supported weakness IDs and records the taxonomy version in every report. See `data/cwe/README.md`. CWE IDs identify weakness types; CWE views and groupings are used only for navigation, never as finding IDs.

## API documentation

FastAPI's interactive documentation is served at `/api/docs`; the OpenAPI schema is at `/api/openapi.json`. Account endpoints are `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, and `/api/auth/me`. Authenticated scan endpoints include `/api/jobs`, `/api/dashboard`, `/api/jobs/{id}`, `/api/jobs/{id}/findings/{finding_id}`, repair/apply/reject routes, SARIF export, patched-project ZIP, and diff download.

## Web application

The web container serves the PatchGuard landing page at `/`, an authenticated dashboard at `/app`, project uploads and scan history at `/app/projects`, findings at `/app/scans`, report exports at `/app/reports`, and the existing firmware upload scanner at `/firmware`. The product preview illustration on the landing page is labeled sample; app metrics and findings come from persisted jobs. This deployment analyzes C/C++ source only. GitHub OAuth can import public repositories for scans; it does not scan pull requests, create fix PRs, check dependency advisories, or run a dedicated secrets scanner.

For local frontend development, run `cd frontend`, `npm install`, and `npm run dev`. To build the production stack, set up the existing `.env` values and run `docker compose up --build`.
