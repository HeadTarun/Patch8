# PatchGuard IoT — Software Requirements Specification

**Version:** 0.1 MVP  
**Taxonomy baseline:** MITRE CWE 5.0 / Schema 8.0  
**Audience:** firmware developers and security reviewers

## 1. Purpose and scope

PatchGuard scans uploaded C/C++ firmware projects, reports selected memory-safety findings with evidence and CWE mappings, and creates reviewable repair proposals. It provides check results for the original and patched copy where safe build/test infrastructure is available.

The detection MVP covers buffer-copy overflow candidates mapped to CWE-120, CWE-121, or CWE-122 when destination context supports the mapping, plus CWE-476 (NULL pointer dereference) from analyzer diagnostics. Semgrep buffer matches remain candidates unless overflow is established. It does not promise exhaustive CWE coverage, zero-day discovery, formal functional equivalence, or performance parity.

## 2. Users and primary flow

1. A developer selects Scan only, Hosted API, or Local Ollama and uploads a ZIP of a C/C++ project.
2. PatchGuard validates the archive, extracts it into a temporary job workspace, and queues an isolated scan.
3. The developer reviews findings, analyzer evidence, CWE description, mapping rationale/confidence, and mitigation guidance.
4. If a repair provider was selected, the developer requests a minimal repair proposal and reviews its diff.
5. The developer applies the change to a copy, reviews build/test evidence, and downloads the patched ZIP, diff, or SARIF report.

Hosted source transfer occurs only after the user selected Hosted API and clicks Generate repair. Scanning does not send source to a model.

## 3. Functional requirements

| ID | Requirement |
| --- | --- |
| FR-01 | Accept ZIP uploads up to 25 MB and standalone `.c`/`.cpp` files up to 200 KB; require `.h` files to be inside ZIPs. Reject path traversal, symlink entries, excessive entry counts, unsupported/empty source, invalid UTF-8, and expanded content above 100 MB. |
| FR-02 | Run Clang Static Analyzer, Cppcheck, and custom Semgrep rules in the restricted, non-root worker. Normalize findings and suspicious candidates with source location, analyzer/rule, evidence, classification, and CWE mapping only when supported by the evidence. Report analyzer failures explicitly. |
| FR-03 | Use the bundled MITRE CWE 5.0 XML data; return taxonomy and schema versions in the API and report; use CWE IDs for findings and never use a view/grouping ID as a finding. |
| FR-04 | Show CWE description, direct MITRE link, mitigation guidance, analyzer evidence, mapping rationale, and whether the weakness is in the 2025 Top 25. Top 25 membership is contextual, not a firmware risk score. |
| FR-05 | Generate a repair proposal from the finding and its CWE guidance using an explicitly selected hosted or Ollama provider. Reject responses targeting a different file or returning an unchanged/oversized file. |
| FR-06 | Apply a proposal to a copied workspace, preserve the uploaded source, and make the unified diff and patched ZIP downloadable. |
| FR-07 | Report build, tests, sanitizers, and performance separately as passed, failed, running, not available, or not measured. Never infer success for a check that did not run. |
| FR-08 | Export SARIF 2.1.0 with CWE taxonomy 5.0 and source locations. |
| FR-09 | Expire job state and files after one hour; delete expired job rows and workspace directories in the worker. |

## 4. Interfaces and data

### HTTP API

- `GET /api/health` — app and taxonomy health.
- `GET /api/weaknesses` — supported CWE catalog entries and pinned version.
- `POST /api/jobs` — multipart ZIP or standalone `.c`/`.cpp` and optional `provider` (`none`, `hosted`, or `ollama`, default `none`); returns a job ID.
- `GET /api/jobs/{id}` — job state, findings, and evidence statuses.
- `POST /api/jobs/{id}/repair/{finding_id}` — create a model-backed proposal.
- `POST /api/jobs/{id}/apply/{repair_id}` — apply the proposal to a copy and queue offline validation.
- `GET /api/jobs/{id}/sarif` — SARIF 2.1.0 export.
- `GET /api/jobs/{id}/diff` and `/download` — unified diff and patched ZIP.

### Finding record

Each finding includes a stable identifier, relative file path, line, analyzer rule, message, CWE object/ID, mapping confidence and rationale, analyzer confidence, analyzer severity, evidence note, and `risk_context: not_assessed`. CVSS is not assigned to source findings.

## 5. Non-functional and security requirements

- **Persistence and queue:** Supabase Postgres stores job metadata and pending-work state. Workers claim jobs atomically using `FOR UPDATE SKIP LOCKED`; no Redis service is required. Uploaded source and repair proposal files stay in the expiring local workspace volume.
- **Isolation:** API, web, and worker are separate Compose services. The web container publishes the UI on a host-facing edge network and reaches the API through a private internal network; the API port is not published directly. The worker runs as a non-root user with dropped capabilities, read-only root filesystem, and CPU/memory/PID limits. The worker needs database egress to Supabase; untrusted build/test commands run under bubblewrap with separate network and filesystem namespaces.
- **Privacy:** source remains in temporary storage; the hosted model receives only the selected finding’s relevant file after explicit provider selection and repair action. API keys stay in server environment variables.
- **Resource bounds:** enforce upload, extracted-size, file-count, per-command time, and output-size limits.
- **Integrity:** patching never overwrites the source workspace. Downloaded evidence identifies taxonomy version and validation status.
- **Performance:** optional `.patchguard/benchmark.json` supplies an argument-array command and 2–5 runs; PatchGuard records median baseline/patched wall time and relative delta in the offline sandbox. It does not infer a pass/fail threshold from noisy timing data.
- **Deployment:** Docker Compose on a Linux VM behind operator-managed HTTPS termination. Supabase connection strings are server-side secrets. The default published port binds to localhost; the MVP has no user authentication and must not be exposed directly to the public internet.

## 6. Acceptance criteria

- Unit checks cover the pinned taxonomy/version, the four supported CWE entries, SARIF taxonomy/findings and candidates, file validation, and ZIP traversal handling. Controlled vulnerable and safe fixtures cover the buffer candidate rules and CWE-476 diagnostics.
- Vulnerable and safe sample pairs exist for each supported CWE; the evaluation script reports case-level TP/FP/FN/TN and precision/recall by CWE.
- A completed scan displays source evidence and separate analyzer/mapping confidence; no contextual-risk or CVSS claim is fabricated.
- A repair can be proposed, reviewed, applied to a copy, and downloaded. Build/test statuses reflect actual sandbox results.
- The UI builds, Compose configuration parses, and the stack exposes the UI at `http://localhost:8000`.
- Juliet evaluation uses a separately downloaded NIST SARD Juliet C/C++ subset and records per-CWE metrics; synthetic examples alone are not presented as production accuracy.
