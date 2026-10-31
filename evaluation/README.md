# CWE evaluation

The `fixtures/detection` directory contains five vulnerable and five safe examples for buffer-copy risks and CWE-476. Buffer examples are evaluated as Semgrep candidates when CWE context can be inferred. They are reproducible smoke inputs, not representative coverage claims.

Run the included controlled fixtures from the backend directory with all configured analyzers available:

```sh
python ../evaluation/evaluate.py ../evaluation/fixtures/detection ../evaluation/fixtures/detection/manifest.csv ../evaluation/results.csv
```

For benchmark evaluation, download NIST SARD Juliet C/C++ 1.3 separately and prepare a CSV manifest with columns `path,expected_cwe,vulnerable`. Each row points to one test case directory or source file. Run from the backend container or another environment with Clang, Cppcheck, and Semgrep installed:

```sh
python evaluation/evaluate.py /path/to/juliet-root evaluation/manifest.csv evaluation/results.csv
```

The summary reports case-level TP/FP/FN/TN per CWE. Juliet has synthetic test cases; pair it with real firmware samples and manual review before making product performance claims.
