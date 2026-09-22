"""Base schema and provenance metadata for AEGIS-WM records."""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


SCHEMA_VERSION = "1.0.0"
PARSER_VERSION = "0.1.0"


class ProvenanceMetadata(BaseModel):
    """Cryptographic provenance and audit tracking attached to extracted records."""

    schema_version: str = Field(default=SCHEMA_VERSION, description="Schema version identifier")
    source_file_hash: str = Field(..., description="SHA-256 hash of the input file")
    extraction_config_hash: str = Field(
        ..., description="SHA-256 hash of the extraction configuration"
    )
    start_timestamp: float = Field(..., description="Epoch timestamp of start observation")
    end_timestamp: float = Field(..., description="Epoch timestamp of end observation")
    provenance_reference: str = Field(
        ..., description="Reference URI or identifier of source file/chunk"
    )
    parser_version: str = Field(default=PARSER_VERSION, description="Parser implementation version")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this record was generated",
    )
