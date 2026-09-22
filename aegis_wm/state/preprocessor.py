"""Leakage-safe feature preprocessing fitted strictly on training data."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np
import torch


class StateFeatureScaler:
    """
    Standardizes state feature vectors: x_norm = (x - mean) / std.
    Strict zero-leakage enforcement: only fit on the training partition.
    Saved to JSON format (no unsafe pickle deserialization).
    """

    def __init__(self, eps: float = 1e-6):
        self.eps = eps
        self.mean: Optional[np.ndarray] = None
        self.std: Optional[np.ndarray] = None
        self.feature_dim: Optional[int] = None
        self.fitted: bool = False

    def fit(self, x: np.ndarray | torch.Tensor) -> "StateFeatureScaler":
        """
        Calculates mean and standard deviation across training windows.
        x: [N, D] or [batch, context_length, D]
        """
        if isinstance(x, torch.Tensor):
            arr = x.detach().cpu().numpy()
        else:
            arr = np.asarray(x)

        if arr.ndim == 3:
            # Flatten batch and time dimensions for feature statistics
            arr = arr.reshape(-1, arr.shape[-1])

        self.mean = np.nanmean(arr, axis=0)
        self.std = np.nanstd(arr, axis=0)
        # Ensure zero std is replaced with 1.0 to prevent divide-by-zero
        self.std = np.where(self.std < self.eps, 1.0, self.std)
        self.feature_dim = arr.shape[-1]
        self.fitted = True
        return self

    def transform(self, x: np.ndarray | torch.Tensor) -> np.ndarray | torch.Tensor:
        """Transforms features using fitted training statistics."""
        if not self.fitted:
            raise RuntimeError("StateFeatureScaler must be fitted on training data before transform.")

        is_torch = isinstance(x, torch.Tensor)
        device = x.device if is_torch else None

        if is_torch:
            arr = x.detach().cpu().numpy()
        else:
            arr = np.asarray(x, dtype=np.float32)

        normed = (arr - self.mean) / (self.std + self.eps)
        normed = np.nan_to_num(normed, nan=0.0, posinf=5.0, neginf=-5.0)

        if is_torch:
            res = torch.from_numpy(normed).to(dtype=torch.float32)
            if device:
                res = res.to(device)
            return res
        return normed

    def inverse_transform(self, x: np.ndarray | torch.Tensor) -> np.ndarray | torch.Tensor:
        """Denormalizes features back to original scale."""
        if not self.fitted:
            raise RuntimeError("Scaler must be fitted before inverse_transform.")

        is_torch = isinstance(x, torch.Tensor)
        device = x.device if is_torch else None

        if is_torch:
            arr = x.detach().cpu().numpy()
        else:
            arr = np.asarray(x, dtype=np.float32)

        orig = (arr * (self.std + self.eps)) + self.mean

        if is_torch:
            res = torch.from_numpy(orig).to(dtype=torch.float32)
            if device:
                res = res.to(device)
            return res
        return orig

    def save_to_file(self, file_path: Path | str) -> None:
        """Saves scaler state to a secure JSON file."""
        if not self.fitted:
            raise RuntimeError("Cannot save unfitted scaler.")
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "feature_dim": self.feature_dim,
            "eps": self.eps,
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
        }
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_from_file(cls, file_path: Path | str) -> "StateFeatureScaler":
        """Loads scaler state from a secure JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        scaler = cls(eps=data.get("eps", 1e-6))
        scaler.feature_dim = data["feature_dim"]
        scaler.mean = np.array(data["mean"], dtype=np.float32)
        scaler.std = np.array(data["std"], dtype=np.float32)
        scaler.fitted = True
        return scaler
