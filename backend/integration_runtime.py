"""Real analyzer and fail-closed sandbox probe; run inside the worker image."""
import json
import os
from pathlib import Path
import shutil
import tempfile

from scanner import analyze
from worker import validate_build, verify_repair_security


def main():
    fixtures = Path(os.environ.get("PATCH8_DEMO_ROOT", "/demo"))
    with tempfile.TemporaryDirectory(prefix="patch8-runtime-", dir="/work") as temporary:
        root = Path(temporary)
        vulnerable = root / "vulnerable"
        safe = root / "safe"
        shutil.copytree(fixtures / "vulnerable", vulnerable)
        shutil.copytree(fixtures / "safe", safe)
        original = analyze(vulnerable)
        comparison = analyze(safe)
        targets = [finding for finding in original["findings"] if (finding.get("cwe") or {}).get("id") == "CWE-476"]
        assert original["scan_status"] == "COMPLETED", original["analyzer_status"]
        assert targets, "Expected supported CWE-476 finding in the controlled fixture."
        assert comparison["scan_status"] == "COMPLETED" and not comparison["findings"], comparison
        check = verify_repair_security(safe, {"findings": original["findings"], "repair": {"finding_id": targets[0]["id"]}})
        assert check["status"] == "passed", check
        checks = validate_build(root, safe)
        print(json.dumps({"original_scan": original["scan_status"], "original_findings": len(original["findings"]),
                          "safe_scan": comparison["scan_status"], "safe_findings": len(comparison["findings"]),
                          "target_security_rescan": check, "build_checks": checks}, indent=2))


if __name__ == "__main__":
    main()
