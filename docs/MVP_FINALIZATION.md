# Patch8 local MVP finalization audit

Audit date: 2026-11-01. Scope: C/C++, public GitHub repositories, local Docker demonstration. No public deployment, private repositories, billing, team administration, or PR automation was added.

## Implemented changes

- Shared archive validation rejects unsafe cross-platform paths, symlinks/special files, duplicate normalized names, encryption, corruption, binary sources, and count/byte limits. Actual decompressed bytes are bounded. Single wrappers normalize consistently, including repeated directory names; multi-project roots remain intact. Failed ingestion removes its temporary project.
- Scan execution and analyzer coverage remain separate. Failed/partial/missing coverage cannot be shown as a clean scan. Original analyzer severity is preserved, with unsupported risk severities displayed as **Not assessed** in totals and filters.
- Acceptance recomputes verification from actual checks. Security rescan must pass; any failed check blocks acceptance. Human review, explicit partial acknowledgement, source/candidate hashes, and original preservation remain required. Acceptance holds a database row lock and compensates its filesystem move if persistence fails.
- Verification claims atomically become non-claimable `verifying`. Scan leases renew and expire to an explicit failure without automatically repeating uploaded build scripts. Explanation, disposition, rejection, and acceptance updates lock the latest payload instead of replacing stale snapshots. Deep repair queue claims now include the deep generation stage.
- Build scripts receive a disposable source copy inside bubblewrap. There is no unsandboxed fallback. Compile-database flags use an allowlist excluding compiler plugins and arbitrary file-output options.
- Both frontends use asynchronous repair operations and serial polling, review/partial acknowledgements, and recoverable diagnostics. Legacy scans retain a job URL for refresh recovery. Requests discard stale finding responses. Uploads handle non-JSON errors, network failures, timeouts, and aborts. Temporary session-service failures show retry rather than redirecting as invalid credentials.
- Projects exposes public GitHub import; repository pagination and source/branch/commit provenance are retained. Provider tokens stay in callback memory. Authenticated GitHub API redirects are restricted before a token could leave the API origin. Browser mutation requests reject foreign origins.
- Patch8 uses shared charcoal/blue/cyan tokens and accurate C/C++ sample content. Unsupported pricing/PR/dependency claims were removed. The full-page particle canvas floats continuously, responds to the pointer, and respects reduced motion. Internal compatibility names for cookies, tables, volumes, and existing export metadata remain unchanged.
- Configuration now lists required authentication settings and consistent Ollama defaults. Direct dotenv imports have an explicit dependency. Added deterministic backend runner, lint/browser tooling, real database/runtime/demo probes, and vulnerable/safe CMake/CTest fixtures.

## Validation record

Unit and UI contract tests use controlled mocks; they do not establish live Supabase, OAuth, model, analyzer, or sandbox availability.

| Check | Evidence |
|---|---|
| Isolated backend suite with updated dependencies | 87 tests passed; writable `.test-work`, external HTTP blocked by runner |
| Python correctness lint | Ruff `E9,F63,F7,F82` passed |
| TypeScript / ESLint | Both TypeScript projects and configured ESLint passed; repeated after final edits |
| Real PostgreSQL integration | Disposable PostgreSQL 17: exclusive claims, lease expiry, concurrent mutations, anonymous denial and two-owner resource isolation passed |
| Browser behavior | Chrome validated floating particles, reduced motion, session retry, upload failure recovery; final production viewport results recorded below |
| Production and Linux runtime | Pending final image/runtime checks; see final results below |
| Live Supabase / Ollama / Groq / GitHub | Pending integration outcomes; see final results below |

The earlier full-suite stall was a Windows restricted-process asyncio/socket-pair startup issue. Bounded execution with a writable test directory and authorized process access completed. Cold Next.js route compilation exceeded the initial browser timeout; it was increased and the checks rerun. These environmental failures were not silently counted as passes.

## Dependency audit

Compatible updates: Vite 6.4.5, PostCSS 8.5.18, python-multipart 0.0.31, python-dotenv 1.2.2, FastAPI 0.140.12 with Starlette 1.8.0. Backend regression tests passed against these versions. FastAPI releases that require OpenTelemetry API >=1.44 conflict with Semgrep's ~=1.37 pin, so the compatible release is retained.

- `npm audit --omit=dev`: zero reported vulnerabilities. Full frontend audit: 11 moderate development-tool dependency advisories, no high or critical. The remaining minimatch update requires an incompatible major version for existing lint consumers; no forced major override was applied.
- `pip-audit -r backend/requirements.txt`: five advisories in Semgrep-pinned `mcp==1.29.0` and `opentelemetry-api==1.37.0`. The current Semgrep 1.183.0 pins prevent compatible replacement. Patch8 invokes Semgrep CLI, not its MCP server; this narrows exposure but does not erase the findings. No claim of a vulnerability-free worker image is made.

Sources: [FastAPI releases](https://fastapi.tiangolo.com/release-notes/), [Semgrep releases](https://github.com/semgrep/semgrep/releases), [minimatch advisory](https://github.com/advisories/GHSA-g3hv-75wg-m249), [PostCSS advisory](https://github.com/advisories/GHSA-r28c-9q8g-f849). Audit results describe the registry state at execution time, not a permanent guarantee.

## Reproduce

Use the root README for configuration and `examples/demo/README.md` for the demonstration. Preserve existing `.env` values and application volumes. The opt-in integration scripts do not create public resources or automatically accept model proposals.

```powershell
# Unit checks (isolated virtual environment)
.test-work/qa-tools/Scripts/python.exe backend/run_tests.py
.test-work/qa-tools/Scripts/python.exe -m ruff check backend --select E9,F63,F7,F82

# Disposable PostgreSQL, with no mounted application volume
docker run --rm -d --name patch8-finalization-test-db -p 127.0.0.1:55439:5432 -e POSTGRES_PASSWORD=patch8-tests-only postgres:17-alpine
$env:PATCH8_TEST_DB_URL='postgresql://postgres:patch8-tests-only@127.0.0.1:55439/postgres'
.test-work/qa-tools/Scripts/python.exe backend/integration_db.py
docker stop patch8-finalization-test-db

# App and real analyzer probe under existing worker restrictions
docker compose config --quiet
docker compose build
docker compose up -d
docker compose run --rm --no-deps -v ./examples/demo:/demo:ro -v ./backend/integration_runtime.py:/app/integration_runtime.py:ro worker python integration_runtime.py
.test-work/qa-tools/Scripts/python.exe backend/integration_demo.py

# Production browser checks
cd frontend
npm run typecheck
npm run lint
npm run test:browser
```

## Final results and release gate

**Not Yet Ready while live release-gate checks remain unverified.** This section is updated with observed results during implementation. A partially verified proposal requires successful security rescan plus human acknowledgement; an unavailable sandbox never becomes a fabricated build pass. GitHub OAuth requires a real consenting user session and is not established by mocked repository tests.
