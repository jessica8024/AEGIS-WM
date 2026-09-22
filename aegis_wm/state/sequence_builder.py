"""Builds chronological sequences (context length m, forecast horizon K) from window states."""

from typing import Dict, List, Optional, Tuple
import numpy as np
import torch
from aegis_wm.schemas.state import NetworkWindowState, TemporalSequence


class SequenceBuilder:
    """Extracts sliding context windows [t-m+1, ..., t] and future targets [t+1, ..., t+K]."""

    def __init__(self, context_length: int = 12, forecast_horizon: int = 6):
        self.context_length = context_length
        self.forecast_horizon = forecast_horizon

    def build_sequences(
        self, states: List[NetworkWindowState]
    ) -> List[TemporalSequence]:
        """
        Builds strongly-typed TemporalSequence objects from window states.
        Preserves strict temporal causality: no future data ever enters context_windows.
        """
        total_len = len(states)
        needed = self.context_length + self.forecast_horizon
        if total_len < needed:
            return []

        sequences: List[TemporalSequence] = []
        for i in range(total_len - needed + 1):
            ctx = states[i : i + self.context_length]
            fut = states[i + self.context_length : i + needed]
            seq = TemporalSequence(
                sequence_id=f"seq_{ctx[-1].window_index}_{ctx[-1].start_timestamp}",
                context_windows=ctx,
                future_windows=fut,
            )
            sequences.append(seq)

        return sequences

    def sequences_to_tensors(
        self, sequences: List[TemporalSequence]
    ) -> Dict[str, torch.Tensor]:
        """
        Converts list of TemporalSequence objects into PyTorch tensors:
        - 'x': [batch, context_length, feature_dim]
        - 'y_state': [batch, forecast_horizon, feature_dim]
        - 'y_stage': [batch, forecast_horizon] (LongTensor)
        - 'y_risk': [batch, forecast_horizon] (FloatTensor)
        - 'timestamps': [batch, context_length + forecast_horizon]
        """
        if not sequences:
            return {}

        x_list = []
        y_state_list = []
        y_stage_list = []
        y_risk_list = []
        time_list = []

        for seq in sequences:
            # Context features S[t-m+1, ..., t]
            ctx_feats = [w.feature_vector for w in seq.context_windows]
            x_list.append(ctx_feats)

            # Future features S[t+1, ..., t+K]
            fut_feats = [w.feature_vector for w in seq.future_windows]
            fut_stages = [int(w.ground_truth_stage) for w in seq.future_windows]
            fut_risks = [1.0 if w.is_compromised else 0.0 for w in seq.future_windows]

            y_state_list.append(fut_feats)
            y_stage_list.append(fut_stages)
            y_risk_list.append(fut_risks)

            all_ts = [w.start_timestamp for w in seq.context_windows] + [
                w.start_timestamp for w in seq.future_windows
            ]
            time_list.append(all_ts)

        return {
            "x": torch.tensor(x_list, dtype=torch.float32),
            "y_state": torch.tensor(y_state_list, dtype=torch.float32),
            "y_stage": torch.tensor(y_stage_list, dtype=torch.long),
            "y_risk": torch.tensor(y_risk_list, dtype=torch.float32),
            "timestamps": torch.tensor(time_list, dtype=torch.float64),
        }
