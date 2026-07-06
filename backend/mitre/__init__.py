"""
backend.mitre — MITRE ATT&CK Mapping Module
============================================
[Module 2.3 — Week 2, Phase 2B]

RESPONSIBILITY
--------------
Map detected anomalous events to MITRE ATT&CK techniques and tactics
using a hardcoded event-type → technique lookup table and SHAP explanations.

DATA FLOW
---------
LogEvent + SHAPExplanation (from Explainability)
    → EventToTechniqueMapper
    → List[MITRETechniqueId] (e.g., ["T1059", "T1548"])
    → Attack Graph Module

FUTURE CONTENTS
---------------
- mapper.py         EventToTechniqueMapper — event_type + feature → technique
- data/             attack_reference.json (technique graph loaded here)
- models/           TechniqueMatch schema
- validator.py      Validates technique IDs against loaded ATT&CK version

EVENT → TECHNIQUE MAPPING TABLE (hardcoded, MVP)
-------------------------------------------------
Event Type           | Indicator              | Technique(s)
---------------------|------------------------|----------------
ProcessCreate        | cmd.exe, powershell    | T1059 (Command Interpreter)
ProcessCreate        | mimikatz               | T1003 (Credential Dumping)
UserLoginFailed      | high frequency         | T1110 (Brute Force)
PrivilegeEscalation  | any                    | T1548 (Abuse Elevation Control)
NetworkConnect       | unusual subnet         | T1021 (Remote Services)
RegistryModify       | HKLM\\System           | T1112 (Modify Registry)
DnsQuery             | high entropy domain    | T1071 (Application Layer Protocol)
ModbusWrite          | unusual registers      | T0831 (Manipulation of Control)

INTEGRATION CONTRACT
--------------------
Input:  LogEvent, SHAPExplanation
Output: List[TechniqueMatch] {
    technique_id:   MITRETechniqueId (e.g., "T1059")
    tactic:         str (e.g., "Execution")
    confidence:     ConfidenceScore
    matched_on:     str (which event field triggered the match)
}

DEPENDENCIES
------------
- backend.shared.types      MITRETechniqueId, MITRETacticId
- backend.core.constants    MITRE_TECHNIQUE_PREFIX, MITRE_ATTACK_VERSION
- backend.explainability    SHAPExplanation (for feature-based matching)

FEATURE FLAG
------------
settings.feature_mitre_enabled = True to activate
"""
