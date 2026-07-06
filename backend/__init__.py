"""
CyberShield Backend Package
============================
AI-Driven Cyber Resilience Platform for Critical National Infrastructure.

Package Structure
-----------------
backend/
├── core/           Cross-cutting infrastructure (config, logging, exceptions)
├── shared/         Shared types, base models, and utilities
├── ingestion/      [Module 1.2] Log Collection & Ingestion
├── normalization/  [Module 1.3] Log Normalization & Parsing
├── features/       [Module 1.4] Feature Engineering & Baseline
├── detection/      [Module 2.1] Isolation Forest Anomaly Detection
├── explainability/ [Module 2.2] SHAP Explainability
├── mitre/          [Module 2.3] MITRE ATT&CK Mapping
├── graph/          [Module 2.4] Attack Graph Reasoning (NetworkX)
├── llm/            [Module 3.1] LLM Alert Enrichment (Claude)
├── response/       [Module 3.2] Autonomous Response Engine
├── audit/          [Module 3.3] Audit Logging & Forensics
├── dashboard/      [Module 4.1] Metrics Dashboard API
└── api/            FastAPI Application Layer
"""

__version__ = "0.1.0"
__module__ = "foundation"
