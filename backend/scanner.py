from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from taxonomy import get_weakness

SOURCE_EXTENSIONS = {".c", ".cpp", ".h"}
CWES = ("CWE-120", "CWE-121", "CWE-122", "CWE-476")
CLANG_CWE_RULES = {"core.NullDereference": "direct"}
RULES_PATH = Path(__file__).with_name("semgrep.yml")


def source_files(root: Path) -> list[Path]:
    ignored = {".git", "node_modules", "build", "dist", "vendor"}
    return [
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
        and not any(part in ignored for part in path.relative_to(root).parts)
    ]


def _finding(root: Path, file: Path, line: int, rule: str, message: str, source_tool: str,
             cwe_id: str | None, classification: str, confidence: str, rationale: str,
             severity: str, evidence: str | None = None) -> dict:
    relative = file.resolve().relative_to(root.resolve()).as_posix()
    fingerprint = hashlib.sha256(f"{relative}:{line}:{rule}:{message}".encode()).hexdigest()[:16]
    return {
        "id": fingerprint,
        "file": relative,
        "line": max(1, line),
        "rule_id": rule,
        "message": message,
        "source_tool": source_tool,
        "source_tools": [source_tool],
        "classification": classification,
        "cwe": get_weakness(cwe_id) if cwe_id else None,
        "mapping_confidence": confidence,
        "analyzer_confidence": "not assessed",
        "severity": severity,
        "risk_context": "not_assessed",
        "mapping_rationale": rationale,
        "evidence": evidence or message,
    }


def parse_cppcheck_output(root: Path, xml_text: str) -> list[dict]:
    report = ET.fromstring(xml_text)
    findings = []
    for error in report.findall("./errors/error"):
        if error.get("id") != "nullPointer":
            continue
        location = error.find("location")
        if location is None:
            continue
        file = Path(location.get("file", ""))
        if not file.is_absolute():
            file = root / file
        try:
            file.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        if not file.is_file():
            continue
        message = error.get("msg", "Possible null pointer dereference")
        findings.append(_finding(
            root, file, int(location.get("line", "1")), error.get("id", "nullPointer"), message,
            "Cppcheck", "CWE-476", "STATIC_ANALYSIS_FINDING", "high",
            "Cppcheck nullPointer diagnostic maps to CWE-476.", error.get("severity", "warning"),
            error.findtext("verbose") or message,
        ))
    return findings


def _cppcheck(root: Path, files: list[Path]) -> dict:
    if not shutil.which("cppcheck"):
        return {"status": "failed", "error": "Cppcheck is not installed.", "findings": []}
    try:
        result = subprocess.run(
            ["cppcheck", "--enable=warning", "--inline-suppr", "--error-exitcode=0", "--xml", "--xml-version=2", *map(str, files)],
            cwd=root, capture_output=True, text=True, timeout=40, check=False,
        )
        findings = parse_cppcheck_output(root, result.stderr)
        if result.returncode:
            return {"status": "failed", "error": result.stderr[-1000:] or f"Cppcheck exited with {result.returncode}.", "findings": findings}
        return {"status": "completed", "error": None, "findings": findings}
    except (OSError, subprocess.TimeoutExpired, ET.ParseError) as exc:
        return {"status": "failed", "error": str(exc)[:1000], "findings": []}


def _clang(root: Path, files: list[Path]) -> dict:
    if not shutil.which("clang"):
        return {"status": "failed", "error": "Clang Static Analyzer is not installed.", "findings": []}
    findings = []
    errors = []
    deadline = time.monotonic() + 25
    limited = len(files) > 80
    for file in files[:80]:
        if time.monotonic() >= deadline:
            limited = True
            break
        try:
            result = subprocess.run(
                ["clang", "--analyze", "-Xanalyzer", "-analyzer-output=text", str(file)],
                cwd=root, capture_output=True, text=True, timeout=3, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(str(exc))
            continue
        combined = result.stderr + "\n" + result.stdout
        if result.returncode:
            errors.append(f"{file.name}: {combined[-500:] or f'exited with {result.returncode}'}")
        for line in combined.splitlines():
            match = re.search(r"(.+?):(\d+):\d+: warning: (.+?) \[([\w.]+)\]", line)
            if not match:
                continue
            raw_file, line_number, message, rule = match.groups()
            if rule not in CLANG_CWE_RULES and not ("null" in message.lower() and "derefer" in message.lower()):
                continue
            path = Path(raw_file)
            if not path.is_absolute():
                path = root / path
            try:
                path.resolve().relative_to(root.resolve())
                findings.append(_finding(root, path, int(line_number), rule, message, "Clang Static Analyzer",
                    "CWE-476", "STATIC_ANALYSIS_FINDING", CLANG_CWE_RULES.get(rule, "inferred"),
                    "Clang null-dereference diagnostic maps to CWE-476.", "warning", combined.strip()))
            except (OSError, ValueError):
                continue
    if not findings and errors and len(errors) >= min(len(files), 80):
        return {"status": "failed", "error": "; ".join(errors)[:1000], "findings": []}
    status = "partial" if errors or limited else "completed"
    error = "; ".join(errors)[:1000] or ("Analysis limit reached." if limited else None)
    return {"status": status, "error": error, "findings": findings}


def _semgrep(root: Path, files: list[Path]) -> dict:
    if not shutil.which("semgrep"):
        return {"status": "failed", "error": "Semgrep is not installed.", "findings": []}
    try:
        result = subprocess.run(
            ["semgrep", "--quiet", "--metrics=off", "--json", "--config", str(RULES_PATH), *map(str, files)],
            cwd=root, capture_output=True, text=True, timeout=40, check=False,
        )
        payload = json.loads(result.stdout or "{}")
        findings = []
        for item in payload.get("results", []):
            path = (root / item.get("path", "")).resolve()
            try:
                path.relative_to(root.resolve())
            except ValueError:
                continue
            if not path.is_file():
                continue
            rule = item.get("check_id", "semgrep.buffer-copy")
            start = item.get("start", {})
            message = item.get("extra", {}).get("message", "Potentially unsafe buffer operation.")
            destination = item.get("extra", {}).get("metavars", {}).get("$DEST", {}).get("abstract_content", "")
            cwe_id = "CWE-120"
            rationale = "The matched copy/format operation does not receive a destination capacity; overflow is a candidate and is not proven."
            if destination:
                try:
                    source_text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    source_text = ""
                var = re.escape(destination.strip())
                line_index = max(0, int(start.get("line", 1)) - 1)
                context = source_text.splitlines()[line_index] if source_text.splitlines() else ""
                if re.search(rf"\b(?:char|unsigned\s+char)\s+{var}\s*\[", context):
                    cwe_id = "CWE-121"
                    rationale = "The destination is declared as a local character array; a stack-based overflow is a candidate, not confirmed."
                elif re.search(rf"\b(?:char|unsigned\s+char)\s*\*\s*{var}\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", context):
                    cwe_id = "CWE-122"
                    rationale = "The destination is initialized from a heap allocation; a heap-based overflow is a candidate, not confirmed."
            findings.append(_finding(
                root, path, int(start.get("line", 1)), rule, message, "Semgrep", cwe_id,
                "SUSPICIOUS_CANDIDATE", "not assessed",
                rationale,
                "warning", item.get("extra", {}).get("lines", "").strip() or message,
            ))
        errors = payload.get("errors", [])
        if result.returncode not in (0, 1) or errors:
            error = result.stderr[-1000:] or "; ".join(str(item.get("message", item)) for item in errors)[:1000] or f"Semgrep exited with {result.returncode}."
            status = "partial" if findings else "failed"
            return {"status": status, "error": error, "findings": findings}
        return {"status": "completed", "error": None, "findings": findings}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"status": "failed", "error": str(exc)[:1000], "findings": []}


def analyze(root: Path) -> dict:
    files = source_files(root)
    if not files:
        statuses = {name: {"status": "failed", "error": "No supported C/C++ source files found.", "findings": []}
                    for name in ("Clang Static Analyzer", "Cppcheck", "Semgrep")}
    else:
        statuses = {
            "Clang Static Analyzer": _clang(root, files),
            "Cppcheck": _cppcheck(root, files),
            "Semgrep": _semgrep(root, files),
        }
    by_key: dict[tuple, dict] = {}
    for tool_result in statuses.values():
        for finding in tool_result["findings"]:
            key = (finding["file"], finding["line"], finding["cwe"]["id"] if finding["cwe"] else None,
                   finding["rule_id"] if finding["classification"] == "SUSPICIOUS_CANDIDATE" else None)
            if key in by_key:
                item = by_key[key]
                if finding["source_tool"] not in item["source_tools"]:
                    item["source_tools"].append(finding["source_tool"])
                if finding["evidence"] not in item["evidence"]:
                    item["evidence"] += "\n" + finding["evidence"]
            else:
                by_key[key] = finding
    findings = list(by_key.values())
    states = [item["status"] for item in statuses.values()]
    scan_status = "FAILED" if all(state == "failed" for state in states) else "PARTIAL" if any(state != "completed" for state in states) else "COMPLETED"
    return {
        "scan_status": scan_status,
        "findings": findings,
        "source_files": len(files),
        "analyzer_status": {name: {"status": item["status"], "error": item["error"]} for name, item in statuses.items()},
        "analyzers": list(statuses),
        "summary": {
            "total": len(findings),
            "candidates": sum(item["classification"] == "SUSPICIOUS_CANDIDATE" for item in findings),
            "by_cwe": {cwe: sum(1 for finding in findings if finding["cwe"] and finding["cwe"]["id"] == cwe) for cwe in CWES},
        },
    }


def sarif_report(job_id: str, findings: list[dict]) -> dict:
    cwe_ids = sorted({finding["cwe"]["id"] for finding in findings if finding.get("cwe")})
    rule_weaknesses: dict[str, set[str]] = {}
    for finding in findings:
        if finding.get("cwe"):
            rule_weaknesses.setdefault(finding["rule_id"], set()).add(finding["cwe"]["id"])
    rules = [
        {"id": rule_id, "shortDescription": {"text": rule_id},
         "properties": {"tags": ["security", *[f"external/cwe/{cwe.lower()}" for cwe in sorted(rule_weaknesses.get(rule_id, set()))]]}}
        for rule_id in sorted({finding["rule_id"] for finding in findings})
    ]
    results = []
    for finding in findings:
        result = {
            "ruleId": finding["rule_id"],
            "level": "error" if finding.get("severity") == "error" else "warning",
            "message": {"text": finding["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["file"]}, "region": {"startLine": finding["line"]}}}],
            "properties": {"classification": finding.get("classification"), "sourceTools": finding.get("source_tools", [])},
        }
        if finding.get("cwe"):
            cwe = finding["cwe"]
            result["taxa"] = [{"id": cwe["id"].removeprefix("CWE-"), "toolComponent": {"name": "CWE"}}]
            result["properties"].update({"mappingConfidence": finding.get("mapping_confidence"), "mappingRationale": finding.get("mapping_rationale"), "analyzerConfidence": finding.get("analyzer_confidence"), "contextualRisk": "not_assessed"})
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "PatchGuard", "informationUri": "https://cwe.mitre.org/", "rules": rules}},
            "taxonomies": [{"name": "CWE", "version": "5.0", "informationUri": "https://cwe.mitre.org/", "taxa": [{"id": item, "name": get_weakness(item)["name"], "helpUri": get_weakness(item)["url"]} for item in cwe_ids]}],
            "results": results,
        }],
    }
