"""
backend.graph — Attack Graph Reasoning Module (NetworkX)
=========================================================
[Module 2.4 — Week 2, Phase 2B]

RESPONSIBILITY
--------------
Build a directed attack graph from MITRE ATT&CK technique relationships,
then reason over detected techniques to produce ranked attack chain
hypotheses (multi-stage attack scenarios).

DATA FLOW
---------
List[MITRETechniqueId] (from MITRE Mapping)
    → AttackGraphBuilder.build_graph()
    → nx.DiGraph (nodes=techniques, edges=prerequisite relationships)
    → ChainDetector.detect_chains()
    → List[AttackChain] sorted by probability (top-3)
    → LLM Module

FUTURE CONTENTS
---------------
- builder.py        AttackGraphBuilder — load data/attack_reference.json → DiGraph
- detector.py       ChainDetector — shortest-path chain detection
- scorer.py         ChainScorer — probability = product of anomaly scores
- predictor.py      NextStagePredictor — predict next ATT&CK technique
- models/           AttackChain, ChainHypothesis
- router.py         GET /api/v1/attack_chains?alert_id=...

GRAPH STRUCTURE
---------------
Nodes: MITRETechniqueId strings ("T1059", "T1021", etc.)
Edges: A → B means "B commonly follows A in an attack progression"
       Weight: empirical co-occurrence probability from ATT&CK Navigator

CHAIN DETECTION ALGORITHM
--------------------------
1. Load detected_techniques as start nodes
2. For each pair: find all simple paths of length 2–4
3. Score each path: probability = Π(anomaly_score[technique_i])
4. Normalise by path length
5. Return top-3 chains by probability

INTEGRATION CONTRACT
--------------------
Input:
  detected_techniques: List[MITRETechniqueId]
  anomaly_scores:       dict[MITRETechniqueId, AnomalyScore]

Output: List[AttackChain] {
    chain_id:       ChainId
    techniques:     List[MITRETechniqueId]
    chain_name:     str (e.g., "Credential Access → Lateral Movement → Persistence")
    probability:    ConfidenceScore
    rank:           int (1 = most likely)
    predicted_next: MITRETechniqueId | None
}

PERFORMANCE TARGET
------------------
Chain detection must complete in < 500ms (small graph, < 500 nodes).

DEPENDENCIES
------------
- networkx                  DiGraph, shortest_simple_paths
- backend.mitre             TechniqueMatch
- backend.shared.types      MITRETechniqueId, ChainId, ConfidenceScore

FEATURE FLAG
------------
settings.feature_graph_enabled = True to activate
"""
