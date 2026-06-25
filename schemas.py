"""
Pydantic models for structured data throughout the pipeline.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IOC(BaseModel):
    value: str
    ioc_type: IOCType
    confidence: ConfidenceLevel
    regex_confirmed: bool = False
    source: str = "llm"  # "regex", "llm", or "both"


class SafetyFinding(BaseModel):
    category: str  # "prompt_injection" | "sensitive_data"
    matched_pattern: str
    excerpt: str
    severity: str  # "high" | "medium"


class MITRECandidate(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: ConfidenceLevel
    evidence: str


class DetectionRule(BaseModel):
    title: str
    description: str
    rule_yaml: str
    basis: str  # what behavior/IOC triggered this


class LLMResponse(BaseModel):
    """Strict schema for the JSON the LLM must return."""
    summary: str
    attacker_behaviors: list[str]
    candidate_iocs: list[str]
    mitre_candidates: list[dict]
    detection_hypotheses: list[str]
    uncertainties: list[str]


class AnalystReport(BaseModel):
    input_file: str
    safety_findings: list[SafetyFinding]
    summary: str
    iocs: list[IOC]
    attacker_behaviors: list[str]
    mitre_mappings: list[MITRECandidate]
    detection_rules: list[DetectionRule]
    detection_hypotheses: list[str]
    uncertainties: list[str]
    llm_raw_response: Optional[dict] = None
