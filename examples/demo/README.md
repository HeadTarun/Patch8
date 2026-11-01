# Patch8 controlled demonstration

`vulnerable/` intentionally dereferences a null pointer. `safe/` contains a reference fix for comparison; it is not substituted for an AI-generated patch.

Both projects include CMake and two CTest cases. The original should pass the ordinary-pointer test and fail the null-pointer test. The reference fix should pass both, including sanitizer checks where the isolated environment is available.

1. Start the Compose stack and sign in.
2. Upload `vulnerable/` with the folder picker, or ZIP its contents (a single archive wrapper is supported).
3. Review the real analyzer statuses and the CWE-476 finding in `main.c`.
4. Request an explanation, then a standard repair. Confirm the reported provider. Automatic mode tries Ollama before Groq; cloud fallback sends bounded source context to Groq.
5. Inspect the original source, proposed diff, compiler diagnostics, tests, sanitizers, and security rescan.
6. Accept only an eligible candidate after reviewing it. Partial verification requires a separate acknowledgement and always requires the security rescan to pass.
7. Download the repaired copy and SARIF report. The original remains unchanged.
8. Optionally scan `safe/` independently to compare real outputs.

Model output is nondeterministic. A rejected proposal, unavailable check, or failed verification must remain visible. Never present this reference fix as a live AI result.

Public GitHub scans use the same ingestion pipeline. If demonstrating GitHub, use an existing public repository you control that contains a supported C/C++ project; this task does not publish or modify any repository.
