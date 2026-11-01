"""Versioned, language-neutral records for scanner evidence."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

T = TypeVar("T")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class FactState(StrEnum):
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"


class Fact(StrictModel, Generic[T]):
    state: FactState = FactState.UNKNOWN
    value: T | None = None

    @model_validator(mode="after")
    def validate_state(self):
        if (self.state == FactState.KNOWN) != (self.value is not None):
            raise ValueError("KNOWN facts require a value; UNKNOWN facts must omit it.")
        return self


class Language(StrEnum):
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"


class OperationType(StrEnum):
    BUFFER_WRITE = "BUFFER_WRITE"
    REFERENCE_ACCESS = "REFERENCE_ACCESS"
    UNKNOWN = "UNKNOWN"


class ValueOrigin(StrEnum):
    FUNCTION_RETURN = "FUNCTION_RETURN"
    ALLOCATION = "ALLOCATION"
    PARAMETER = "PARAMETER"
    CONSTANT = "CONSTANT"
    FIELD = "FIELD"
    UNKNOWN = "UNKNOWN"


class VulnerabilityFamily(StrEnum):
    BUFFER_BOUNDARY_VIOLATION = "BUFFER_BOUNDARY_VIOLATION"
    NULL_OR_INVALID_REFERENCE_ACCESS = "NULL_OR_INVALID_REFERENCE_ACCESS"
    UNKNOWN = "UNKNOWN"


class AnalysisType(StrEnum):
    PATTERN_BASED = "PATTERN_BASED"
    STATIC_DIAGNOSTIC = "STATIC_DIAGNOSTIC"
    PATH_SENSITIVE = "PATH_SENSITIVE"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Classification(StrEnum):
    STATIC_ANALYSIS_FINDING = "STATIC_ANALYSIS_FINDING"
    SUSPICIOUS_CANDIDATE = "SUSPICIOUS_CANDIDATE"


class ScanStatus(StrEnum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class SourceLocation(StrictModel):
    file_path: str
    line: int = Field(ge=1)
    column: Fact[int] = Field(default_factory=Fact)

    @model_validator(mode="after")
    def require_relative_path(self):
        path = PurePosixPath(self.file_path)
        windows_path = PureWindowsPath(self.file_path)
        if (path.is_absolute() or windows_path.is_absolute() or windows_path.drive
                or ".." in path.parts or ".." in windows_path.parts or "\\" in self.file_path
                or not self.file_path):
            raise ValueError("IR source paths must be non-empty and relative.")
        if self.column.state == FactState.KNOWN and self.column.value < 1:
            raise ValueError("IR columns must be one-based.")
        return self


class Operation(StrictModel):
    type: OperationType = OperationType.UNKNOWN
    object_id: Fact[str] = Field(default_factory=Fact)
    operation_id: Fact[str] = Field(default_factory=Fact)


class SecurityProperties(StrictModel):
    nullability: Literal["NULLABLE", "POSSIBLY_NULL", "NON_NULL", "UNKNOWN"] = "UNKNOWN"
    null_check_present: Fact[bool] = Field(default_factory=Fact)
    buffer_capacity: Fact[int] = Field(default_factory=Fact)
    input_length: Fact[int] = Field(default_factory=Fact)
    guard_condition: Fact[str] = Field(default_factory=Fact)
    data_flow: Fact[str] = Field(default_factory=Fact)
    control_flow: Fact[str] = Field(default_factory=Fact)

    @model_validator(mode="after")
    def validate_nonnegative_sizes(self):
        for fact in (self.buffer_capacity, self.input_length):
            if fact.state == FactState.KNOWN and fact.value < 0:
                raise ValueError("Known buffer sizes must be non-negative.")
        return self


class AnalyzerEvidence(StrictModel):
    source_tool: str
    source_tools: list[str] = Field(default_factory=list)
    diagnostic_id: str
    message: str
    raw_evidence: str
    analysis_type: AnalysisType
    confidence: Confidence = Confidence.UNKNOWN
    severity: str = "warning"


class IRRecord(StrictModel):
    ir_version: Literal["1.0"] = "1.0"
    finding_id: str
    language: Language
    source: SourceLocation
    rule_id: str
    message: str
    mapping_confidence: str
    analyzer_confidence: str
    severity: str
    risk_context: str
    mapping_rationale: str
    function: Fact[str] = Field(default_factory=Fact)
    value_origin: ValueOrigin = ValueOrigin.UNKNOWN
    operation: Operation
    family: VulnerabilityFamily
    properties: SecurityProperties = Field(default_factory=SecurityProperties)
    cwe_id: Literal["CWE-120", "CWE-121", "CWE-122", "CWE-476"] | None = None
    classification: Classification
    evidence: AnalyzerEvidence
    limitations: list[str] = Field(default_factory=list)


class AnalyzerState(StrictModel):
    status: ScanStatus
    error: str | None = None


class Coverage(StrictModel):
    languages: list[Language] = Field(default_factory=list)
    analyzer_status: dict[str, AnalyzerState] = Field(default_factory=dict)
    supported_families: list[VulnerabilityFamily] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class IRAnalysis(StrictModel):
    product: Literal["PatchProof"] = "PatchProof"
    ir_version: Literal["1.0"] = "1.0"
    mode: Literal["shadow", "unified"]
    status: ScanStatus
    coverage: Coverage
    records: list[IRRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
