# 3. Data Leakage Prevention and Entity Pseudonymization

Date: 2026-09-21

## Status
Accepted

## Context
Many published network intrusion detection research papers suffer from severe data leakage:
1. Fitting scalers across the full dataset prior to train/test splits.
2. Randomly splitting flows from the same attack session or host pair.
3. Allowing IP string literals as features, causing models to memorize specific IP addresses rather than behavioral patterns.
4. Allowing future temporal data into historical context windows.

## Decision
1. Apply keyed HMAC-SHA256 pseudonymization to all IP addresses, retaining topological consistency within a capture while preventing memorization of static IP strings.
2. Enforce strictly chronological, session-aware and capture-day splits (e.g. Monday/Tuesday for training, Thursday for validation, Friday for testing).
3. Preprocessing pipelines (scalers, imputers, normalizers) must strictly be fitted only on the training partition and serialized as separate artifacts with model checkpoints.
4. Implement automated programmatic leakage tests verifying zero timestamp overlap, zero session overlap, and zero scaler leakage across splits.

## Consequences
- Evaluation metrics will reflect true out-of-sample generalization performance on unseen temporal sequences and attack sessions.
