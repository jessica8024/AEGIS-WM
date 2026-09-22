"""Dataset split manager and automated leakage verification engine."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
import torch
from aegis_wm.schemas.state import NetworkWindowState, TemporalSequence


class LeakageVerificationError(AssertionError):
    """Raised when data leakage between partitions is detected."""
    pass


class DatasetSplitter:
    """Partitions network states chronologically with isolation gaps, testing for zero leakage."""

    @staticmethod
    def split_windows_with_gap(
        windows: List[NetworkWindowState],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        gap_windows: int = 18,  # context_length (12) + forecast_horizon (6)
    ) -> Tuple[List[NetworkWindowState], List[NetworkWindowState], List[NetworkWindowState]]:
        """
        Partitions raw temporal windows into train, val, test with an explicit purge gap
        between partitions. This prevents sliding context/target windows from overlapping
        across split boundaries.
        """
        if not windows:
            return [], [], []

        sorted_wins = sorted(windows, key=lambda w: w.start_timestamp)
        n = len(sorted_wins)

        train_end = int(n * train_ratio)
        val_start = train_end + gap_windows
        val_end = int(n * (train_ratio + val_ratio))
        test_start = val_end + gap_windows

        train_wins = sorted_wins[:train_end]
        val_wins = sorted_wins[val_start:val_end] if val_start < val_end else []
        test_wins = sorted_wins[test_start:] if test_start < n else []

        return train_wins, val_wins, test_wins

    @staticmethod
    def chronological_split(
        sequences: List[TemporalSequence],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        gap_sequences: int = 18,
    ) -> Tuple[List[TemporalSequence], List[TemporalSequence], List[TemporalSequence]]:
        """
        Partitions sliding sequences chronologically with a purge gap between partitions.
        """
        if not sequences:
            return [], [], []

        sorted_seqs = sorted(sequences, key=lambda s: s.context_windows[-1].end_timestamp)
        n = len(sorted_seqs)

        train_end = int(n * train_ratio)
        val_start = min(n, train_end + gap_sequences)
        val_end = int(n * (train_ratio + val_ratio))
        test_start = min(n, val_end + gap_sequences)

        train_seqs = sorted_seqs[:train_end]
        val_seqs = sorted_seqs[val_start:val_end] if val_start < val_end else []
        test_seqs = sorted_seqs[test_start:] if test_start < n else []

        return train_seqs, val_seqs, test_seqs

    @staticmethod
    def verify_zero_leakage(
        train_seqs: List[TemporalSequence],
        val_seqs: List[TemporalSequence],
        test_seqs: List[TemporalSequence],
    ) -> Dict[str, bool]:
        """
        Runs comprehensive data leakage checks:
        1. Timestamp causality: train max time <= val min time <= test min time.
        2. Sequence ID overlap: zero shared sequence IDs.
        3. Future causality: within each sequence, context windows precede future windows.
        """
        results = {
            "no_train_val_overlap": True,
            "no_val_test_overlap": True,
            "no_sequence_id_leakage": True,
            "temporal_causality_valid": True,
        }

        # Check internal temporal causality within every sequence
        for seq_list in [train_seqs, val_seqs, test_seqs]:
            for s in seq_list:
                ctx_max = max(w.end_timestamp for w in s.context_windows)
                if s.future_windows:
                    fut_min = min(w.start_timestamp for w in s.future_windows)
                    if fut_min < ctx_max:
                        results["temporal_causality_valid"] = False
                        raise LeakageVerificationError(
                            f"Future contamination in sequence {s.sequence_id}: "
                            f"Future start {fut_min} < Context end {ctx_max}"
                        )

        # Check partition boundary timestamps
        if train_seqs and val_seqs:
            train_max = max(
                s.future_windows[-1].end_timestamp
                if s.future_windows
                else s.context_windows[-1].end_timestamp
                for s in train_seqs
            )
            val_min = min(s.context_windows[0].start_timestamp for s in val_seqs)
            if train_max > val_min:
                results["no_train_val_overlap"] = False
                raise LeakageVerificationError(
                    f"Timestamp overlap detected between train (max={train_max}) and val (min={val_min})"
                )

        if val_seqs and test_seqs:
            val_max = max(
                s.future_windows[-1].end_timestamp
                if s.future_windows
                else s.context_windows[-1].end_timestamp
                for s in val_seqs
            )
            test_min = min(s.context_windows[0].start_timestamp for s in test_seqs)
            if val_max > test_min:
                results["no_val_test_overlap"] = False
                raise LeakageVerificationError(
                    f"Timestamp overlap detected between val (max={val_max}) and test (min={test_min})"
                )

        # Check disjoint sequence IDs
        train_ids = set(s.sequence_id for s in train_seqs)
        val_ids = set(s.sequence_id for s in val_seqs)
        test_ids = set(s.sequence_id for s in test_seqs)

        if train_ids.intersection(val_ids) or val_ids.intersection(test_ids) or train_ids.intersection(test_ids):
            results["no_sequence_id_leakage"] = False
            raise LeakageVerificationError("Shared sequence IDs found across partitions.")

        return results
