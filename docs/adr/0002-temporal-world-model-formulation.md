# 2. Temporal World Model State Transition Formulation

Date: 2026-09-21

## Status
Accepted

## Context
Standard intrusion detection systems classify individual packets or flows independently, failing to capture the temporal progression of advanced multi-stage attacks. Furthermore, predicting future states via simple point prediction (Mean Squared Error) fails to capture aleatoric and epistemic uncertainty inherent in network dynamics.

## Decision
1. Formulate the network state transition as a conditional probability distribution:
   $$P(S_{t+1} \mid S_{t-m+1}, \dots, S_t)$$
   where $S_t \in \mathbb{R}^D$ represents aggregated network state in time window $t$.
2. Implement a latent temporal encoder (Transformer or GRU) mapping historical windows to latent state $z_t \in \mathbb{R}^d$.
3. Parameterize the transition model as a multivariate Gaussian with diagonal covariance outputting mean $\mu_{z, t+1}$ and bounded log variance $\log \sigma^2_{z, t+1}$, optimized using Gaussian Negative Log-Likelihood (NLL).
4. Perform multi-step forecasting through recursive autoregressive rollout for $K$ steps, feeding forecasted states back into the temporal context with scheduled sampling during training to prevent rollout collapse.

## Consequences
- The model directly outputs calibrated predictive uncertainty across forecast horizons.
- The system enables proactive detection before exploitation completes, rather than retrospective alert generation.
