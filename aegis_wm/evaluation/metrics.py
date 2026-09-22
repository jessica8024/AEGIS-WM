"""Comprehensive evaluation metrics for stage classification, infiltration risk, and forecasting."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    auc,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def compute_expected_calibration_error(
    y_true: np.ndarray, y_prob: np.ndarray, num_bins: int = 10
) -> float:
    """
    Computes Expected Calibration Error (ECE) for binary infiltration probabilities.
    Groups predictions into bins [0, 0.1), [0.1, 0.2), ... and calculates weighted
    absolute difference between confidence and empirical accuracy.
    """
    if len(y_true) == 0:
        return 0.0

    bins = np.linspace(0.0, 1.0, num_bins + 1)
    ece = 0.0
    total_samples = len(y_true)

    for i in range(num_bins):
        bin_lower = bins[i]
        bin_upper = bins[i + 1]

        if i == num_bins - 1:
            in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper)
        else:
            in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper)

        bin_count = np.sum(in_bin)
        if bin_count > 0:
            bin_acc = np.mean(y_true[in_bin])
            bin_conf = np.mean(y_prob[in_bin])
            ece += (bin_count / total_samples) * abs(bin_acc - bin_conf)

    return float(ece)


def compute_stage_classification_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, num_classes: int = 9
) -> Dict[str, Any]:
    """Computes Macro F1, Weighted F1, Per-class Precision/Recall, and Confusion Matrix."""
    if len(y_true) == 0:
        return {}

    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)

    precision_per_class = precision_score(
        y_true, y_pred, average=None, labels=list(range(num_classes)), zero_division=0
    ).tolist()
    recall_per_class = recall_score(
        y_true, y_pred, average=None, labels=list(range(num_classes)), zero_division=0
    ).tolist()

    cm = confusion_matrix(y_true, y_pred, labels=list(range(num_classes))).tolist()

    return {
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "accuracy": float(acc),
        "balanced_accuracy": float(bal_acc),
        "precision_per_class": precision_per_class,
        "recall_per_class": recall_per_class,
        "confusion_matrix": cm,
    }


def compute_infiltration_prediction_metrics(
    y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.50
) -> Dict[str, Any]:
    """Computes AUROC, AUPRC, Brier Score, ECE, and operating point metrics."""
    if len(y_true) == 0:
        return {}

    # Binary prediction at frozen threshold
    y_pred = (y_prob >= threshold).astype(int)

    # Check if both classes are present for AUROC/AUPRC
    unique_classes = np.unique(y_true)
    if len(unique_classes) > 1:
        auroc = float(roc_auc_score(y_true, y_prob))
        prec_curve, rec_curve, _ = precision_recall_curve(y_true, y_prob)
        auprc = float(auc(rec_curve, prec_curve))
    else:
        auroc = 1.0 if unique_classes[0] == 0 else 0.0
        auprc = 1.0 if unique_classes[0] == 0 else 0.0

    brier = float(brier_score_loss(y_true, y_prob))
    ece = compute_expected_calibration_error(y_true, y_prob)

    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    # Confusion matrix for false alarm rate
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "auroc": auroc,
        "auprc": auprc,
        "brier_score": brier,
        "expected_calibration_error": ece,
        "threshold_used": threshold,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }


def compute_forecast_state_metrics(
    y_true_states: np.ndarray, y_pred_states: np.ndarray
) -> Dict[str, Any]:
    """
    Computes continuous state forecast error across horizons k=1..K.
    y_true_states: [N, K, D]
    y_pred_states: [N, K, D]
    """
    if len(y_true_states) == 0:
        return {}

    diff = y_pred_states - y_true_states
    mae_per_horizon = np.mean(np.abs(diff), axis=(0, 2)).tolist()
    rmse_per_horizon = np.sqrt(np.mean(diff ** 2, axis=(0, 2))).tolist()

    overall_mae = float(np.mean(np.abs(diff)))
    overall_rmse = float(np.sqrt(np.mean(diff ** 2)))

    return {
        "overall_mae": overall_mae,
        "overall_rmse": overall_rmse,
        "mae_by_horizon": mae_per_horizon,
        "rmse_by_horizon": rmse_per_horizon,
        "rollout_degradation_curve": rmse_per_horizon,
    }


def compute_lead_time_metrics(
    y_true_series: List[int],
    y_prob_forecasts: List[List[float]],
    window_duration_seconds: float = 5.0,
    threshold: float = 0.50,
) -> Dict[str, Any]:
    """
    Measures lead time: How many seconds/windows before an actual compromise stage
    did the model forecast risk >= threshold at horizon k?
    """
    lead_times_windows = []
    first_compromise_idx = None

    for idx, is_comp in enumerate(y_true_series):
        if is_comp != 0:
            first_compromise_idx = idx
            break

    if first_compromise_idx is None:
        return {"attacks_observed": False, "mean_lead_time_seconds": 0.0}

    # Check forecasts made prior to first_compromise_idx
    for t in range(first_compromise_idx):
        if t < len(y_prob_forecasts):
            horizon_probs = y_prob_forecasts[t]
            # Does any future forecast horizon target reach or exceed first_compromise_idx?
            for k_step, prob in enumerate(horizon_probs, start=1):
                projected_time = t + k_step
                if projected_time >= first_compromise_idx and prob >= threshold:
                    lead_windows = first_compromise_idx - t
                    lead_times_windows.append(lead_windows)
                    break

    if lead_times_windows:
        mean_lead_win = float(np.mean(lead_times_windows))
        max_lead_win = float(np.max(lead_times_windows))
        return {
            "attacks_observed": True,
            "mean_lead_time_windows": mean_lead_win,
            "mean_lead_time_seconds": mean_lead_win * window_duration_seconds,
            "max_lead_time_seconds": max_lead_win * window_duration_seconds,
            "earliest_alert_windows_prior": max_lead_win,
        }

    return {
        "attacks_observed": True,
        "mean_lead_time_windows": 0.0,
        "mean_lead_time_seconds": 0.0,
        "earliest_alert_windows_prior": 0.0,
    }
