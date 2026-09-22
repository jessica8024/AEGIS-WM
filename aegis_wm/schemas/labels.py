"""Attack stage ontology, MITRE mapping structures, and confidence tiers."""

from enum import Enum, IntEnum
from typing import List, Optional
from pydantic import BaseModel, Field


class AttackStageEnum(IntEnum):
    """Canonical 9-class attack progression ontology."""

    BENIGN = 0
    RECONNAISSANCE = 1
    INITIAL_ACCESS = 2
    EXECUTION_OR_ESTABLISHMENT = 3
    LATERAL_MOVEMENT = 4
    COMMAND_AND_CONTROL = 5
    EXFILTRATION = 6
    IMPACT = 7
    UNKNOWN_MALICIOUS = 8

    @classmethod
    def get_display_name(cls, value: int) -> str:
        names = {
            cls.BENIGN: "Benign",
            cls.RECONNAISSANCE: "Reconnaissance",
            cls.INITIAL_ACCESS: "Initial Access",
            cls.EXECUTION_OR_ESTABLISHMENT: "Execution / Establishment",
            cls.LATERAL_MOVEMENT: "Lateral Movement",
            cls.COMMAND_AND_CONTROL: "Command & Control",
            cls.EXFILTRATION: "Exfiltration",
            cls.IMPACT: "Impact",
            cls.UNKNOWN_MALICIOUS: "Unknown Malicious",
        }
        return names.get(value, f"Stage_{value}")


class EvidenceConfidenceEnum(str, Enum):
    """Standardized evidence confidence levels."""

    DIRECTLY_SUPPORTED = "Directly supported"
    BEHAVIOURALLY_CONSISTENT = "Behaviourally consistent"
    INSUFFICIENT_EVIDENCE = "Insufficient evidence"


class StageLabel(BaseModel):
    """Structured attack stage annotation linked to MITRE ATT&CK."""

    stage_id: AttackStageEnum = Field(..., description="Integer stage identifier (0-8)")
    stage_name: str = Field(..., description="Canonical stage string")
    mitre_tactic: Optional[str] = Field(None, description="ATT&CK tactic ID (e.g. TA0043)")
    mitre_technique: Optional[str] = Field(None, description="ATT&CK technique ID (e.g. T1046)")
    confidence: EvidenceConfidenceEnum = Field(EvidenceConfidenceEnum.BEHAVIOURALLY_CONSISTENT)
    rationale: str = Field("", description="Analytical justification for stage assignment")
    source_label: Optional[str] = Field(None, description="Original raw label from dataset")
