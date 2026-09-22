"""TemporalGraphWorldModel: Graph Neural Network extension combining topology and temporal dynamics."""

from typing import Any, Dict, List, Optional, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F
from aegis_wm.models.world_model import TemporalWorldModel


class GraphMessagePassingLayer(nn.Module):
    """
    Native PyTorch message-passing layer (GraphSAGE-style) operating on communication graphs.
    Avoids rigid PyG binary dependencies while delivering full message-passing capability:
    h_v = W_self * h_v + W_neigh * AGG_{u in N(v)}( W_edge * e_{uv} + h_u )
    """

    def __init__(self, in_node_dim: int, in_edge_dim: int, out_dim: int):
        super().__init__()
        self.w_self = nn.Linear(in_node_dim, out_dim)
        self.w_neigh = nn.Linear(in_node_dim, out_dim)
        self.w_edge = nn.Linear(in_edge_dim, in_node_dim)
        self.norm = nn.LayerNorm(out_dim)

    def forward(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
    ) -> torch.Tensor:
        """
        node_features: [num_nodes, in_node_dim]
        edge_index: [2, num_edges] (src, dst)
        edge_attr: [num_edges, in_edge_dim]
        """
        num_nodes = node_features.size(0)
        self_feat = self.w_self(node_features)

        if edge_index.size(1) == 0:
            return self.norm(F.gelu(self_feat))

        src_nodes = edge_index[0]
        dst_nodes = edge_index[1]

        # Edge-conditioned messages
        edge_emb = self.w_edge(edge_attr)
        messages = node_features[src_nodes] + edge_emb

        # Mean aggregation into destination nodes
        aggregated = torch.zeros(num_nodes, messages.size(1), device=node_features.device)
        ones = torch.zeros(num_nodes, 1, device=node_features.device)

        aggregated.index_add_(0, dst_nodes, messages)
        ones.index_add_(0, dst_nodes, torch.ones(edge_index.size(1), 1, device=node_features.device))
        aggregated = aggregated / torch.clamp(ones, min=1.0)

        out = self_feat + self.w_neigh(aggregated)
        return self.norm(F.gelu(out))


class TemporalGraphWorldModel(nn.Module):
    """
    Extension world model that encodes communication graph topology alongside
    global feature vectors, pooling graph state embeddings into the temporal transition model.
    """

    def __init__(
        self,
        feature_dim: int = 36,
        node_feature_dim: int = 10,
        edge_feature_dim: int = 5,
        graph_embedding_dim: int = 32,
        d_model: int = 128,
        latent_dim: int = 64,
        forecast_horizon: int = 6,
        num_stages: int = 9,
    ):
        super().__init__()
        self.graph_embedding_dim = graph_embedding_dim

        # Graph message passing encoder
        self.gnn1 = GraphMessagePassingLayer(node_feature_dim, edge_feature_dim, 64)
        self.gnn2 = GraphMessagePassingLayer(64, edge_feature_dim, graph_embedding_dim)

        # Host-level risk head (for entity attribution)
        self.host_risk_head = nn.Sequential(
            nn.Linear(graph_embedding_dim, 32),
            nn.GELU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

        # Temporal World Model backbone accepting concatenated [vector_features, graph_embedding]
        combined_dim = feature_dim + graph_embedding_dim
        self.temporal_backbone = TemporalWorldModel(
            feature_dim=combined_dim,
            d_model=d_model,
            latent_dim=latent_dim,
            num_stages=num_stages,
            forecast_horizon=forecast_horizon,
        )

    def encode_graph_window(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Encodes a single window graph:
        Returns:
            graph_emb: [1, graph_embedding_dim] (pooled global graph state)
            node_risks: [num_nodes] (per-host risk probabilities)
        """
        h = self.gnn1(node_features, edge_index, edge_attr)
        h = self.gnn2(h, edge_index, edge_attr)

        # Global mean pool across all active hosts in window
        graph_emb = torch.mean(h, dim=0, keepdim=True)
        node_risks = self.host_risk_head(h).squeeze(-1)

        return graph_emb, node_risks

    def forward(
        self,
        x_vector: torch.Tensor,
        graph_embeddings: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        x_vector: [batch, context_length, feature_dim]
        graph_embeddings: [batch, context_length, graph_embedding_dim]
        """
        combined = torch.cat([x_vector, graph_embeddings], dim=-1)
        return self.temporal_backbone(combined)
