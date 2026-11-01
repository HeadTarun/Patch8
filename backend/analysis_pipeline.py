"""Compatibility-preserving legacy, shadow, and unified analysis modes."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ir_adapters import detect_language, normalize_report
from scanner import CWES, analyze as analyze_legacy, source_files
from vulnerability_engine import evaluate

ANALYSIS_MODES = frozenset({"legacy", "shadow", "unified"})


def validate_analysis_mode(value: str | None) -> str:
    mode = (value or "legacy").strip().lower()
    if mode not in ANALYSIS_MODES:
        raise ValueError(f"ANALYSIS_MODE must be one of: {', '.join(sorted(ANALYSIS_MODES))}.")
    return mode


def _comparison(legacy: list[dict], normalized: list[dict]) -> dict:
    def key(item: dict) -> tuple:
        cwe = item.get("cwe") or {}
        evidence_id = hashlib.sha256(str(item.get("evidence", "")).encode("utf-8")).hexdigest()[:12]
        return item.get("file"), item.get("line"), cwe.get("id"), item.get("classification"), evidence_id

    legacy_by_key = {key(item): item for item in legacy}
    normalized_by_key = {key(item): item for item in normalized}
    matched = sorted(legacy_by_key.keys() & normalized_by_key.keys(), key=str)
    return {
        "matched": [list(item) for item in matched],
        "legacy_only": [legacy_by_key[item] for item in sorted(legacy_by_key.keys() - normalized_by_key.keys(), key=str)],
        "ir_only": [normalized_by_key[item] for item in sorted(normalized_by_key.keys() - legacy_by_key.keys(), key=str)],
        "counts": {
            "legacy": len(legacy),
            "ir": len(normalized),
            "matched": len(matched),
            "legacy_only": len(legacy_by_key.keys() - normalized_by_key.keys()),
            "ir_only": len(normalized_by_key.keys() - legacy_by_key.keys()),
        },
    }


def _summary(findings: list[dict]) -> dict:
    return {
        "total": len(findings),
        "candidates": sum(item.get("classification") == "SUSPICIOUS_CANDIDATE" for item in findings),
        "by_cwe": {cwe: sum(1 for item in findings if item.get("cwe") and item["cwe"].get("id") == cwe) for cwe in CWES},
    }


def _failed_ir_metadata(root: Path, mode: str, report: dict, error: Exception) -> dict:
    statuses = {
        name: {"status": state.get("status", "failed").upper(), "error": state.get("error")}
        for name, state in report.get("analyzer_status", {}).items()
    }
    languages = sorted({detect_language(path.relative_to(root).as_posix()).value for path in source_files(root)})
    return {
        "product": "PatchProof",
        "ir_version": "1.0",
        "mode": mode,
        "status": "FAILED",
        "coverage": {
            "languages": languages,
            "analyzer_status": statuses,
            "supported_families": ["BUFFER_BOUNDARY_VIOLATION", "NULL_OR_INVALID_REFERENCE_ACCESS"],
            "notes": ["Only C/C++ adapters are active in IR version 1.0."],
        },
        "records": [],
        "errors": [f"IR analysis failed: {error}"],
        "findings": [],
        "fallback": "legacy" if mode == "unified" else None,
    }


def run_analysis(root: Path, mode: str = "legacy") -> dict:
    mode = validate_analysis_mode(mode)
    if mode == "legacy":
        return analyze_legacy(root)

    legacy_report = analyze_legacy(root)
    if mode == "shadow":
        # Shadow intentionally runs the analyzers independently for comparison.
        result = dict(legacy_report)
        try:
            ir_source_report = analyze_legacy(root)
            ir = normalize_report(ir_source_report, root, mode)
            normalized_findings = evaluate(ir.records)
            shadow_analysis = {**ir.model_dump(mode="json"), "findings": normalized_findings}
        except Exception as exc:
            shadow_analysis = _failed_ir_metadata(root, mode, legacy_report, exc)
            normalized_findings = []
        shadow_analysis["comparison"] = _comparison(legacy_report.get("findings", []), normalized_findings)
        result["shadow_analysis"] = shadow_analysis
        return result

    result = dict(legacy_report)
    try:
        ir = normalize_report(legacy_report, root, mode)
        findings = evaluate(ir.records)
        result["findings"] = findings
        result["summary"] = _summary(findings)
        result["analysis"] = ir.model_dump(mode="json")
    except Exception as exc:
        result["analysis"] = _failed_ir_metadata(root, mode, legacy_report, exc)
        result["scan_status"] = "PARTIAL" if legacy_report.get("scan_status") != "FAILED" else "FAILED"
    return result
