"""Attack stage ontology and MITRE ATT&CK mapping logic."""

from pathlib import Path
from typing import Dict, Optional
import yaml
from aegis_wm.schemas.labels import AttackStageEnum, EvidenceConfidenceEnum, StageLabel


class AttackStageMapper:
    """Maps dataset labels to canonical 9-stage ontology and MITRE ATT&CK tactics."""

    def __init__(self, mapping_config_path: Optional[Path | str] = None):
        self.mappings: Dict[str, StageLabel] = {}
        self._load_mappings(mapping_config_path)

    def _load_mappings(self, config_path: Optional[Path | str]) -> None:
        """Loads mapping YAML configuration or initializes defaults."""
        default_path = Path("configs/mitre/stage_mapping.yaml")
        path_to_use = Path(config_path) if config_path else default_path

        if path_to_use.exists():
            with open(path_to_use, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                for m in data.get("mappings", []):
                    source = m["source_label"].strip()
                    stage_id = AttackStageEnum(m["stage_id"])
                    conf = EvidenceConfidenceEnum(m.get("confidence", "Behaviourally consistent"))
                    self.mappings[source] = StageLabel(
                        stage_id=stage_id,
                        stage_name=m["target_stage"],
                        mitre_tactic=m.get("mitre_tactic"),
                        mitre_technique=m.get("mitre_technique"),
                        confidence=conf,
                        rationale=m.get("rationale", ""),
                        source_label=source,
                    )
        else:
            # Fallback direct mappings
            self.mappings["BENIGN"] = StageLabel(
                stage_id=AttackStageEnum.BENIGN,
                stage_name="BENIGN",
                confidence=EvidenceConfidenceEnum.DIRECTLY_SUPPORTED,
                rationale="Normal baseline traffic",
                source_label="BENIGN",
            )
            self.mappings["PortScan"] = StageLabel(
                stage_id=AttackStageEnum.RECONNAISSANCE,
                stage_name="RECONNAISSANCE",
                mitre_tactic="TA0043",
                mitre_technique="T1046",
                confidence=EvidenceConfidenceEnum.DIRECTLY_SUPPORTED,
                rationale="Service discovery scan",
                source_label="PortScan",
            )

    def map_label(self, raw_label: Optional[str]) -> StageLabel:
        """Maps a raw dataset label string to a strongly-typed StageLabel."""
        if not raw_label:
            return StageLabel(
                stage_id=AttackStageEnum.BENIGN,
                stage_name="BENIGN",
                confidence=EvidenceConfidenceEnum.DIRECTLY_SUPPORTED,
                rationale="Unlabeled flow default",
            )

        cleaned = str(raw_label).strip()

        # Direct exact match
        if cleaned in self.mappings:
            return self.mappings[cleaned]

        # Case-insensitive substring match
        cleaned_lower = cleaned.lower()
        if "benign" in cleaned_lower:
            return self.mappings.get("BENIGN", StageLabel(stage_id=AttackStageEnum.BENIGN, stage_name="BENIGN"))
        if "portscan" in cleaned_lower or "scan" in cleaned_lower:
            return self.mappings.get("PortScan", StageLabel(stage_id=AttackStageEnum.RECONNAISSANCE, stage_name="RECONNAISSANCE"))
        if "web" in cleaned_lower or "xss" in cleaned_lower or "sql" in cleaned_lower or "patator" in cleaned_lower:
            return StageLabel(
                stage_id=AttackStageEnum.INITIAL_ACCESS,
                stage_name="INITIAL_ACCESS",
                mitre_tactic="TA0001",
                confidence=EvidenceConfidenceEnum.BEHAVIOURALLY_CONSISTENT,
                source_label=cleaned,
            )
        if "infilt" in cleaned_lower:
            return StageLabel(
                stage_id=AttackStageEnum.LATERAL_MOVEMENT,
                stage_name="LATERAL_MOVEMENT",
                mitre_tactic="TA0008",
                confidence=EvidenceConfidenceEnum.BEHAVIOURALLY_CONSISTENT,
                source_label=cleaned,
            )
        if "bot" in cleaned_lower:
            return StageLabel(
                stage_id=AttackStageEnum.COMMAND_AND_CONTROL,
                stage_name="COMMAND_AND_CONTROL",
                mitre_tactic="TA0011",
                confidence=EvidenceConfidenceEnum.DIRECTLY_SUPPORTED,
                source_label=cleaned,
            )
        if "dos" in cleaned_lower or "ddos" in cleaned_lower:
            return StageLabel(
                stage_id=AttackStageEnum.IMPACT,
                stage_name="IMPACT",
                mitre_tactic="TA0040",
                confidence=EvidenceConfidenceEnum.DIRECTLY_SUPPORTED,
                source_label=cleaned,
            )

        # If unknown malicious
        return StageLabel(
            stage_id=AttackStageEnum.UNKNOWN_MALICIOUS,
            stage_name="UNKNOWN_MALICIOUS",
            confidence=EvidenceConfidenceEnum.INSUFFICIENT_EVIDENCE,
            rationale="Unrecognized attack signature",
            source_label=cleaned,
        )
