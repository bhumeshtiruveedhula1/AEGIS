"""
backend.features.extractors.auth — Authentication Feature Extractor
===================================================================
Module 2.2 — Behavioral Feature Engine

Computes 7 authentication behavioral features from Windows auth context
compared against the entity's baseline AuthBaseline.

Features
--------
logon_type_is_novel            : 1.0 if logon_type not in baseline distribution
auth_package_is_novel          : 1.0 if auth_package not in baseline distribution
logon_type_baseline_frequency  : How often this logon_type appeared in baseline
auth_package_baseline_frequency: How often this auth_package appeared in baseline
auth_failure_rate_baseline     : Baseline proportion of failed auth events
auth_event_count_baseline      : Total auth events tracked in baseline
windows_event_id_is_novel      : 1.0 if windows_event_id not in baseline dist

Design notes
------------
- Auth features are only meaningful for DC events (logon_type, auth_package,
  windows_event_id). For other sources, event fields are None and all
  features return 0.0 (not applicable).
- logon_type novelty is a high-value feature for lateral movement detection.
  Network logons (type 3) from a normally interactive account are suspicious.
- auth_failure_rate_baseline gives downstream models a reference rate to
  compare against short-window failure rates (Module 2.3+).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import BaseExtractor, binary, safe_frequency

if TYPE_CHECKING:
    from backend.baseline.models import AuthBaseline, EntityBaseline
    from backend.normalization.models import CanonicalEvent


class AuthExtractor(BaseExtractor):
    """Authentication behavior novelty and baseline comparison features."""

    @property
    def group_name(self) -> str:
        return "auth"

    @property
    def feature_names(self) -> list[str]:
        return [
            "logon_type_is_novel",
            "auth_package_is_novel",
            "logon_type_baseline_frequency",
            "auth_package_baseline_frequency",
            "auth_failure_rate_baseline",
            "auth_event_count_baseline",
            "windows_event_id_is_novel",
        ]

    def extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> dict[str, float]:
        auth: AuthBaseline | None = None
        if baseline is not None:
            auth = baseline.auth

        # If this event has no auth context, all features are 0.0
        has_auth_context = (
            event.logon_type is not None
            or event.auth_package is not None
            or event.windows_event_id is not None
        )
        if not has_auth_context:
            return {name: 0.0 for name in self.feature_names}

        # ── Logon type novelty / frequency ─────────────────────────────────
        logon_novel = 0.0
        logon_freq = 0.0
        if event.logon_type is not None:
            if auth is not None:
                logon_novel = binary(
                    event.logon_type.lower()
                    not in {k.lower() for k in auth.logon_type_distribution}
                )
                logon_freq = safe_frequency(
                    event.logon_type, auth.logon_type_distribution
                )

        # ── Auth package novelty / frequency ───────────────────────────────
        pkg_novel = 0.0
        pkg_freq = 0.0
        if event.auth_package is not None:
            if auth is not None:
                pkg_novel = binary(
                    event.auth_package.lower()
                    not in {k.lower() for k in auth.auth_package_distribution}
                )
                pkg_freq = safe_frequency(
                    event.auth_package, auth.auth_package_distribution
                )

        # ── Auth failure rate ──────────────────────────────────────────────
        auth_fail_rate = 0.0
        if auth is not None:
            auth_fail_rate = min(auth.failure_rate, 1.0)

        # ── Auth event count ───────────────────────────────────────────────
        auth_count = 0.0
        if auth is not None:
            auth_count = float(auth.auth_event_count)

        # ── Windows Event ID novelty ───────────────────────────────────────
        evid_novel = 0.0
        if event.windows_event_id is not None and auth is not None:
            evid_novel = binary(
                str(event.windows_event_id)
                not in auth.windows_event_id_distribution
            )

        return {
            "logon_type_is_novel": logon_novel,
            "auth_package_is_novel": pkg_novel,
            "logon_type_baseline_frequency": logon_freq,
            "auth_package_baseline_frequency": pkg_freq,
            "auth_failure_rate_baseline": auth_fail_rate,
            "auth_event_count_baseline": auth_count,
            "windows_event_id_is_novel": evid_novel,
        }
