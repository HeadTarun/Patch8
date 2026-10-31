# PatchGuard analysis architecture

PatchGuard adds a versioned, language-neutral intermediate representation (IR) around the existing C/C++ analyzer outputs. IR version `1.0` preserves source location, operation family, analyzer identity and raw evidence. Properties such as function, data-flow, guard state, buffer capacity, and input length remain `UNKNOWN` unless an analyzer actually establishes them.

The current adapters normalize Clang Static Analyzer, Cppcheck, and Semgrep results. Clang and Cppcheck diagnostics retain their existing CWE-476 behavior. Semgrep buffer matches remain suspicious candidates; the IR records that they are pattern-based. The shared engine only normalizes those two supported vulnerability families. It does not infer that unknown buffer or nullability facts are safe.

## Modes

Set `ANALYSIS_MODE` for the worker in `.env` and recreate the worker/container to change it:

- `legacy` (default) runs the existing scanner and returns its report unchanged.
- `shadow` runs legacy and IR pipelines independently. Legacy findings remain user-facing; IR records, coverage, and comparison data are added under `report.shadow_analysis`. This mode runs the analyzers twice.
- `unified` runs the analyzer evidence through IR normalization and maps the results back to the existing finding fields. IR inspection data is added under `report.analysis`.

Invalid mode values stop the worker at startup. Keep production on `legacy` until the real analyzer integration and compatibility suite pass.

## Extension boundary

IR version 1.0 has C and C++ adapters. Header files are labeled `unknown` because `.h` alone does not establish whether the translation unit is C or C++. Future language adapters should map their analyzer evidence into the same operations and facts without asserting properties absent from their diagnostics. No syntax parser or additional language analyzer is required by the current implementation.
