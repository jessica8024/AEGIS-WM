"""Feature and temporal attribution using Captum Integrated Gradients and Occlusion."""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import scipy.stats
import torch
from captum.attr import IntegratedGradients
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.schemas.explanation import FeatureAttribution, TemporalAttribution
from aegis_wm.state.window_aggregator import FEATURE_NAMES


class ModelRiskWrapper(torch.nn.Module):
    """Wraps TemporalWorldModel to output scalar infiltration risk for attribution."""

    def __init__(self, model: TemporalWorldModel):
        super().__init__()
        self.model = model

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: [batch, context_length, feature_dim]
        Returns scalar risk probability: [batch, 1]
        """
        z_t = self.model.encode_context(x)
        z_next, _, _ = self.model.step_transition(z_t, sample_stochastic=False)
        _, _, _, risk_prob, _ = self.model.decode_predictions(z_next)
        return risk_prob.unsqueeze(-1)


class AttributionEngine:
    """Computes feature attribution, temporal attribution, and stability metrics."""

    def __init__(self, model: TemporalWorldModel):
        self.model = model
        self.model.eval()
        self.wrapper = ModelRiskWrapper(model)
        self.ig = IntegratedGradients(self.wrapper)

    def attribute_features(
        self,
        x_tensor: torch.Tensor,
        baseline: Optional[torch.Tensor] = None,
        feature_names: Optional[List[str]] = None,
    ) -> Tuple[List[FeatureAttribution], List[TemporalAttribution]]:
        """
        Computes Integrated Gradients attribution across features and time windows.
        x_tensor: [1, context_length, feature_dim]
        baseline: [1, context_length, feature_dim] (default all zeros)
        """
        names = feature_names or FEATURE_NAMES
        if baseline is None:
            baseline = torch.zeros_like(x_tensor)

        device = next(self.model.parameters()).device
        x_in = x_tensor.to(device)
        b_in = baseline.to(device)

        # Compute Integrated Gradients: attributions have shape [1, context_len, feature_dim]
        attributions, delta = self.ig.attribute(
            x_in, baselines=b_in, return_convergence_delta=True, n_steps=25
        )
        attr_np = attributions[0].detach().cpu().numpy()  # [context_len, feature_dim]

        # Aggregate feature contributions across time
        feature_scores = np.mean(attr_np, axis=0)  # [feature_dim]
        abs_sum = np.sum(np.abs(feature_scores)) + 1e-8

        top_feature_list: List[FeatureAttribution] = []
        for i, val in enumerate(feature_scores):
            direction = "increases_risk" if val >= 0 else "decreases_risk"
            rel_imp = float(abs(val) / abs_sum)
            top_feature_list.append(
                FeatureAttribution(
                    feature_name=names[i] if i < len(names) else f"feature_{i}",
                    contribution=float(val),
                    direction=direction,
                    relative_importance=rel_imp,
                )
            )

        # Sort descending by relative importance
        top_feature_list.sort(key=lambda f: f.relative_importance, reverse=True)

        # Temporal attribution across context windows [t-m+1, ..., t]
        window_scores = np.mean(np.abs(attr_np), axis=1)  # [context_len]
        temporal_list: List[TemporalAttribution] = []
        context_len = x_tensor.size(1)

        for w_idx in range(context_len):
            offset = w_idx - context_len + 1  # e.g. -11 ... 0
            temporal_list.append(
                TemporalAttribution(
                    window_index=w_idx,
                    relative_window_offset=offset,
                    timestamp=0.0,
                    contribution=float(window_scores[w_idx]),
                    active_flow_count=0,
                )
            )

        return top_feature_list, temporal_list

    def test_explanation_stability(
        self,
        x_tensor: torch.Tensor,
        noise_std: float = 0.05,
        num_trials: int = 5,
    ) -> float:
        """
        Measures stability of top feature rankings under slight non-critical perturbation.
        Returns average Spearman rank correlation (1.0 = perfectly stable).
        """
        orig_features, _ = self.attribute_features(x_tensor)
        orig_scores = [f.contribution for f in orig_features]

        correlations = []
        for _ in range(num_trials):
            noise = torch.randn_like(x_tensor) * noise_std
            perturbed_x = x_tensor + noise
            pert_features, _ = self.attribute_features(perturbed_x)
            # Map back to original feature order
            pert_map = {f.feature_name: f.contribution for f in pert_features}
            pert_scores = [pert_map.get(f.feature_name, 0.0) for f in orig_features]

            corr, _ = scipy.stats.spearmanr(orig_scores, pert_scores)
            if not np.isnan(corr):
                correlations.append(corr)

        return float(np.mean(correlations)) if correlations else 1.0
