# PatchGuard IoT

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

Open <http://localhost:8000>. The web container publishes this port on the host-facing `edge` network and reaches the API over the private `inside` network. The API itself is not published directly. Upload a project ZIP or a standalone `.c`/`.cpp` file (up to 200 KB); `.h` files must be inside a ZIP. The worker runs Clang Static Analyzer, Cppcheck, and Semgrep as a non-root user. Build/test subprocesses have no network access. Model keys stay on the API service and are never sent to the browser.

Supabase Postgres stores job metadata and acts as the durable queue. The worker claims pending rows with `FOR UPDATE SKIP LOCKED`; no Redis service or Redis socket is used. Source archives and repair proposals remain in the one-hour local `jobs` volume and are removed by worker cleanup.

### Supabase connection troubleshooting

If worker logs report `Network is unreachable` for a `2a05:...` address, the configured direct database hostname resolved to IPv6 but the Docker network has no IPv6 route. In Supabase **Connect**, copy the **Session pooler** string (port `5432`) into `SUPABASE_DB_URL`; for the shared pooler, use `patchguard_backend.<project-ref>` as the username. Keep `sslmode=require`, then recreate the stack with `docker compose down --remove-orphans` and `docker compose up --build`. The worker backs off between connection retries and logs this fix as a hint.

### Repair providers

For hosted repairs, set `OPENAI_API_KEY` and optionally `OPENAI_BASE_URL` and `OPENAI_MODEL` in the environment before starting Compose. Selecting **Hosted API** discloses that relevant source will be sent to that provider.

For Ollama, set `OLLAMA_BASE_URL` and `OLLAMA_MODEL`; the API service must be able to reach that Ollama endpoint. Selecting **Ollama** keeps model traffic on the configured local endpoint.

Without model configuration, scanning and reports still work; repair generation explains how to configure a provider.

## Deployment

Run the Compose stack on a Linux VM behind HTTPS termination (for example, a reverse proxy managed by the operator). Keep the service private until authentication and per-user quotas are configured. The MVP enforces upload, file-count, extracted-size, CPU-time, and wall-clock limits; the analysis worker runs as an unprivileged user and its build/test subprocesses run without network access in bubblewrap. The worker needs egress to Supabase Postgres for queue and job state. Restrict VM egress to the Supabase endpoint where the host firewall supports it. Do not mount Docker sockets or model-provider credentials into the worker.

Uploaded projects and generated artifacts are stored in the `jobs` volume and expire after one hour. Job state and queue rows are stored in Supabase and deleted after expiry by the worker. For production, add authenticated access, monitored quotas, a database backup/retention policy, and external secrets management before exposing it publicly.

## Supported MVP checks

- C/C++ scans: Clang Static Analyzer and Cppcheck report CWE-476 diagnostics; custom Semgrep rules report risky buffer operations as candidates and map CWE-120/121/122 only from available destination context. Analyzer failures are reported as partial or failed scans.
- Repairs: hosted OpenAI-compatible chat-completions API or Ollama chat API.
- Evidence: build and test checks are attempted only for detected CMake/CTest or Make projects. AddressSanitizer/UndefinedBehaviorSanitizer checks are attempted for CMake projects with tests. Performance comparison is opt-in through a project benchmark manifest.
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
