"""Cryptographic utilities: provenance hashing and HMAC-based address pseudonymization."""

import hashlib
import hmac
import os
from pathlib import Path
from typing import Union


DEFAULT_SALT = os.environ.get("AEGIS_PSEUDONYM_SALT", "aegis_wm_secure_local_salt_2026")


def compute_sha256(data: Union[bytes, str, Path]) -> str:
    """Computes SHA-256 hash of a file path, string, or byte array."""
    hasher = hashlib.sha256()
    if isinstance(data, Path) or (isinstance(data, str) and os.path.isfile(data)):
        with open(data, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    elif isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    elif isinstance(data, bytes):
        hasher.update(data)
    else:
        raise TypeError(f"Unsupported data type for sha256: {type(data)}")
    return hasher.hexdigest()


def pseudonymize_ip(ip_address: str, salt: str = DEFAULT_SALT, prefix_len: int = 12) -> str:
    """
    Computes a deterministic, non-reversible pseudonym for an IP address.
    Preserves structural identity during an analysis session without exposing raw IP
    or allowing models to memorize spatial IP strings.
    Format: 'host_<hex12>'
    """
    if not ip_address or ip_address.lower() in {"unknown", "none", "0.0.0.0", ""}:
        return "host_unknown"

    h = hmac.new(salt.encode("utf-8"), ip_address.strip().encode("utf-8"), hashlib.sha256)
    digest = h.hexdigest()[:prefix_len]
    return f"host_{digest}"


def pseudonymize_endpoint(ip_address: str, port: int, salt: str = DEFAULT_SALT) -> str:
    """Computes a pseudonymized endpoint identifier."""
    host_pseudo = pseudonymize_ip(ip_address, salt=salt)
    return f"{host_pseudo}:{port}"
