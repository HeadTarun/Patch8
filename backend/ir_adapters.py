"""Adapt existing analyzer findings into the language-neutral IR."""

from __future__ import annotations

from pathlib import Path

from analysis_ir import (
    AnalysisType,
    AnalyzerEvidence,
    AnalyzerState,
    Classification,
    Confidence,
    Coverage,
    IRAnalysis,
    IRRecord,
    Language,
    Operation,
    OperationType,
    ScanStatus,
    SecurityProperties,
    SourceLocation,
    VulnerabilityFamily,
)
from scanner import source_files

BUFFER_CWES = {"CWE-120", "CWE-121", "CWE-122"}


def detect_language(path: str) -> Language:
    suffix = Path(path).suffix.lower()
    if suffix == ".c":
        return Language.C
    if suffix in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}:
        return Language.CPP
    return Language.UNKNOWN


class AnalyzerAdapter:
    tool_name = "unknown"
    analysis_type = AnalysisType.UNKNOWN

    def normalize(self, finding: dict) -> IRRecord:
        cwe = finding.get("cwe") or {}
        cwe_id = cwe.get("id")
        classification = Classification(finding.get("classification", Classification.STATIC_ANALYSIS_FINDING.value))
        is_buffer = cwe_id in BUFFER_CWES or (cwe_id is None and classification == Classification.SUSPICIOUS_CANDIDATE)
        family = VulnerabilityFamily.BUFFER_BOUNDARY_VIOLATION if is_buffer else (
            VulnerabilityFamily.NULL_OR_INVALID_REFERENCE_ACCESS if cwe_id == "CWE-476" else VulnerabilityFamily.UNKNOWN
        )
        tool = finding.get("source_tool", self.tool_name)
        analysis_type = self.analysis_type
        if tool == "Clang Static Analyzer" and finding.get("rule_id") == "core.NullDereference":
            analysis_type = AnalysisType.PATH_SENSITIVE
        confidence_text = str(finding.get("analyzer_confidence", "")).lower()
        confidence = {
            "high": Confidence.HIGH,
            "medium": Confidence.MEDIUM,
            "low": Confidence.LOW,
        }.get(confidence_text, Confidence.LOW if classification == Classification.SUSPICIOUS_CANDIDATE else Confidence.UNKNOWN)
        properties = SecurityProperties()
        operation_type = OperationType.UNKNOWN
        if family == VulnerabilityFamily.NULL_OR_INVALID_REFERENCE_ACCESS:
            properties.nullability = "POSSIBLY_NULL"
            operation_type = OperationType.REFERENCE_ACCESS
        elif family == VulnerabilityFamily.BUFFER_BOUNDARY_VIOLATION:
            operation_type = OperationType.BUFFER_WRITE
        limitations = []
        if is_buffer:
            limitations.append("Analyzer evidence does not prove that the write exceeds destination capacity.")
        if properties.buffer_capacity.state == "UNKNOWN" or properties.input_length.state == "UNKNOWN":
            limitations.append("Buffer capacity and input length were not established by the analyzer output.")
        if tool == "Semgrep":
            limitations.append("Semgrep result is pattern-based and does not establish path-sensitive reachability.")
        return IRRecord(
            finding_id=str(finding["id"]),
            language=detect_language(finding.get("file", "")),
            source=SourceLocation(file_path=finding["file"], line=max(1, int(finding.get("line", 1)))),
            rule_id=str(finding.get("rule_id", "unknown")),
            message=str(finding.get("message", "")),
            mapping_confidence=str(finding.get("mapping_confidence", "not assessed")),
            analyzer_confidence=str(finding.get("analyzer_confidence", "not assessed")),
            severity=str(finding.get("severity", "warning")),
            risk_context=str(finding.get("risk_context", "not_assessed")),
            mapping_rationale=str(finding.get("mapping_rationale", "")),
            operation=Operation(type=operation_type),
            family=family,
            properties=properties,
            cwe_id=cwe_id,
            classification=classification,
            evidence=AnalyzerEvidence(
                source_tool=tool,
                source_tools=list(finding.get("source_tools") or [tool]),
                diagnostic_id=str(finding.get("rule_id", "unknown")),
                message=str(finding.get("message", "")),
                raw_evidence=str(finding.get("evidence", finding.get("message", ""))),
                analysis_type=analysis_type,
                confidence=confidence,
                severity=str(finding.get("severity", "warning")),
            ),
            limitations=limitations,
        )


class ClangAdapter(AnalyzerAdapter):
    tool_name = "Clang Static Analyzer"
    analysis_type = AnalysisType.STATIC_DIAGNOSTIC


class CppcheckAdapter(AnalyzerAdapter):
    tool_name = "Cppcheck"
    analysis_type = AnalysisType.STATIC_DIAGNOSTIC


class SemgrepAdapter(AnalyzerAdapter):
    tool_name = "Semgrep"
    analysis_type = AnalysisType.PATTERN_BASED


ADAPTERS = {
    "Clang Static Analyzer": ClangAdapter(),
    "Cppcheck": CppcheckAdapter(),
    "Semgrep": SemgrepAdapter(),
}


def normalize_report(report: dict, root: Path, mode: str) -> IRAnalysis:
    records = []
    for finding in report.get("findings", []):
        adapter = ADAPTERS.get(finding.get("source_tool", ""), AnalyzerAdapter())
        records.append(adapter.normalize(finding))
    statuses = {
        name: AnalyzerState(status=state.get("status", "failed").upper(), error=state.get("error"))
        for name, state in report.get("analyzer_status", {}).items()
    }
    languages = sorted({detect_language(path.relative_to(root).as_posix()) for path in source_files(root)}, key=lambda item: item.value)
    return IRAnalysis(
        mode=mode,
        status=str(report.get("scan_status", "FAILED")).upper(),
        coverage=Coverage(
            languages=languages,
            analyzer_status=statuses,
            supported_families=[VulnerabilityFamily.BUFFER_BOUNDARY_VIOLATION, VulnerabilityFamily.NULL_OR_INVALID_REFERENCE_ACCESS],
            notes=["Only C/C++ adapters are active in IR version 1.0.", "Header language remains UNKNOWN without compile-context evidence."],
        ),
        records=records,
        errors=[state.error for state in statuses.values() if state.error],
    )
