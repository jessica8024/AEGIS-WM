# 1. Record Architecture Decisions

Date: 2026-09-21

## Status
Accepted

## Context
AEGIS-WM requires architectural rigor across multiple disciplines: network telemetry processing, deep learning dynamics, explainability, cyber-physical systems safety, and full offline operation.
We need a standardized method to capture all foundational design choices and rationale.

## Decision
We adopt the Architecture Decision Record (ADR) format (Michael Nygard format) to document significant architectural decisions in `docs/adr/`.

## Consequences
- Every major architectural fork (model loss formulation, state windowing, ingestion pipeline, explainability methods) will be formally documented with context, rationale, and consequences.
