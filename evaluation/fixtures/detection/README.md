# Detection fixtures

These 20 small inputs are controlled static-analysis fixtures, not production-accuracy claims. Buffer cases are expected to produce Semgrep suspicious candidates; stack and heap destination declarations support CWE-121 and CWE-122 candidate mappings, while caller-owned buffers map to CWE-120. Safe examples use bounded copies or explicit null guards. Null-pointer cases are expected to be reported only when Clang or Cppcheck produces an actual diagnostic.

Do not execute the vulnerable fixtures. They are intended for static analysis.
