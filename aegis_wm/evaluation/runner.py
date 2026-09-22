"""Evaluation runner executing static, temporal, and persistence baselines on leakage-safe splits."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from aegis_wm.common.logger import logger
from aegis_wm.evaluation.metrics import (
    compute_forecast_state_metrics,
    compute_infiltration_prediction_metrics,
    compute_stage_classification_metrics,
)
from aegis_wm.models.baselines import (
    LSTMClassificationBaseline,
    PersistenceForecaster,
    StaticLogisticBaseline,
    StaticRandomForestBaseline,
)
from aegis_wm.state.preprocessor import StateFeatureScaler


class BaselineBenchmarkRunner:
    """Executes all baselines on identical train/val/test splits and saves reproducible comparison."""

    def __init__(self, output_dir: Path | str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_all_baselines(
        self,
        train_tensors: Dict[str, torch.Tensor],
        val_tensors: Dict[str, torch.Tensor],
        test_tensors: Dict[str, torch.Tensor],
        scaler: StateFeatureScaler,
        forecast_horizon: int = 6,
    ) -> Dict[str, Any]:
        """
        Fits and evaluates:
        1. Persistence forecaster (next state = current state)
        2. Static Logistic Regression (current window features)
        3. Static Random Forest (current window features)
        4. LSTM Sequence Classifier (context sequence -> direct horizon heads)
        """
        logger.info("Running Baseline Benchmark Suite...")

        # Scale inputs using training scaler
        x_train_norm = scaler.transform(train_tensors["x"])
        x_val_norm = scaler.transform(val_tensors["x"])
        x_test_norm = scaler.transform(test_tensors["x"])

        x_train_np = x_train_norm.numpy() if isinstance(x_train_norm, torch.Tensor) else x_train_norm
        x_test_np = x_test_norm.numpy() if isinstance(x_test_norm, torch.Tensor) else x_test_norm

        y_stage_train = train_tensors["y_stage"].numpy()
        y_risk_train = train_tensors["y_risk"].numpy()
        y_stage_test = test_tensors["y_stage"].numpy()
        y_risk_test = test_tensors["y_risk"].numpy()
        y_state_test = test_tensors["y_state"].numpy()

        results: Dict[str, Any] = {}

        # 1. Persistence Baseline
        logger.info("Evaluating Persistence Forecaster...")
        persistence = PersistenceForecaster(forecast_horizon=forecast_horizon)
        pred_states_norm = persistence.predict(x_test_np)
        pred_states_orig = scaler.inverse_transform(pred_states_norm)
        persistence_state_metrics = compute_forecast_state_metrics(y_state_test, pred_states_orig)
        results["persistence_forecaster"] = {
            "model_type": "persistence",
            "description": "Next state equals current observed state S[t]",
            "state_forecast": persistence_state_metrics,
        }

        # 2. Static Logistic Regression
        logger.info("Training & Evaluating Static Logistic Regression...")
        log_reg = StaticLogisticBaseline()
        try:
            log_reg.fit(x_train_np, y_stage_train, y_risk_train)
            lr_risk_probs, lr_stages = log_reg.predict(x_test_np)
            results["logistic_regression_static"] = {
                "model_type": "static_linear",
                "description": "Logistic regression on current window S[t]",
                "infiltration_metrics": compute_infiltration_prediction_metrics(
                    y_risk_test[:, 0], lr_risk_probs
                ),
                "stage_metrics": compute_stage_classification_metrics(
                    y_stage_test[:, 0], lr_stages
                ),
            }
        except Exception as e:
            logger.warning(f"Logistic regression baseline fitting skipped: {e}")
            results["logistic_regression_static"] = {"error": str(e)}

        # 3. Static Random Forest
        logger.info("Training & Evaluating Static Random Forest...")
        rf = StaticRandomForestBaseline(n_estimators=50)
        try:
            rf.fit(x_train_np, y_stage_train, y_risk_train)
            rf_risk_probs, rf_stages = rf.predict(x_test_np)
            results["random_forest_static"] = {
                "model_type": "static_tree_ensemble",
                "description": "Random forest on current window S[t]",
                "infiltration_metrics": compute_infiltration_prediction_metrics(
                    y_risk_test[:, 0], rf_risk_probs
                ),
                "stage_metrics": compute_stage_classification_metrics(
                    y_stage_test[:, 0], rf_stages
                ),
            }
        except Exception as e:
            logger.warning(f"Random forest baseline fitting skipped: {e}")
            results["random_forest_static"] = {"error": str(e)}

        # 4. LSTM Classification Baseline (Temporal, without state transition loss)
        logger.info("Training & Evaluating LSTM Sequence Classifier...")
        feature_dim = x_train_np.shape[-1]
        lstm_model = LSTMClassificationBaseline(
            feature_dim=feature_dim,
            hidden_dim=64,
            num_layers=2,
            forecast_horizon=forecast_horizon,
        )
        optimizer = torch.optim.Adam(lstm_model.parameters(), lr=0.003)
        bce_loss_fn = nn.BCELoss()
        ce_loss_fn = nn.CrossEntropyLoss()

        train_dataset = TensorDataset(
            torch.tensor(x_train_np, dtype=torch.float32),
            train_tensors["y_risk"],
            train_tensors["y_stage"],
        )
        train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)

        lstm_model.train()
        for epoch in range(5):  # fast baseline training
            for batch_x, batch_y_risk, batch_y_stage in train_loader:
                optimizer.zero_grad()
                pred_risk, pred_stage_logits = lstm_model(batch_x)
                loss_risk = bce_loss_fn(pred_risk, batch_y_risk)
                loss_stage = ce_loss_fn(
                    pred_stage_logits.view(-1, 9), batch_y_stage.view(-1)
                )
                loss = loss_risk + loss_stage
                loss.backward()
                optimizer.step()

        lstm_model.eval()
        with torch.no_grad():
            test_x_tensor = torch.tensor(x_test_np, dtype=torch.float32)
            lstm_pred_risk, lstm_pred_stage_logits = lstm_model(test_x_tensor)
            lstm_pred_stages = torch.argmax(lstm_pred_stage_logits, dim=-1).numpy()
            lstm_pred_risk_np = lstm_pred_risk.numpy()

        results["lstm_temporal_classifier"] = {
            "model_type": "temporal_sequence_no_transition",
            "description": "LSTM sequence model without next-state transition loss",
            "infiltration_metrics": compute_infiltration_prediction_metrics(
                y_risk_test[:, 0], lstm_pred_risk_np[:, 0]
            ),
            "stage_metrics": compute_stage_classification_metrics(
                y_stage_test[:, 0], lstm_pred_stages[:, 0]
            ),
        }

        # Save results to JSON
        output_json = self.output_dir / "baselines_benchmark.json"
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        # Generate summary CSV
        summary_rows = []
        for m_name, m_data in results.items():
            inf_met = m_data.get("infiltration_metrics", {})
            stg_met = m_data.get("stage_metrics", {})
            summary_rows.append({
                "model": m_name,
                "type": m_data.get("model_type"),
                "auroc": inf_met.get("auroc", np.nan),
                "auprc": inf_met.get("auprc", np.nan),
                "brier_score": inf_met.get("brier_score", np.nan),
                "macro_f1": stg_met.get("macro_f1", np.nan),
                "accuracy": stg_met.get("accuracy", np.nan),
            })
        pd.DataFrame(summary_rows).to_csv(self.output_dir / "baselines_summary.csv", index=False)
        logger.info(f"Baselines benchmark written to {output_json} and summary CSV.")
        return results
