"""
backend.features.extractors.network — Network Feature Extractor
===============================================================
Module 2.2 — Behavioral Feature Engine

Computes 10 network behavioral features from current event network
fields compared against the entity's baseline NetworkBaseline.

Features
--------
dst_ip_is_novel          : 1.0 if dst_ip not seen in baseline
src_ip_is_novel          : 1.0 if src_ip not seen in baseline
port_is_novel            : 1.0 if port not seen in baseline
protocol_is_novel        : 1.0 if protocol not in baseline distribution
port_baseline_frequency  : How often this port appeared in baseline
protocol_baseline_frequency : How often this protocol appeared in baseline
bytes_out_z_score        : Z-score of bytes_out vs baseline distribution
bytes_out_percentile_rank: Percentile rank of bytes_out vs baseline
unique_dst_ips_baseline  : Count of unique dst IPs tracked in baseline
connection_count_baseline: Total network connection events in baseline

Design notes
------------
- Novel = "not seen in baseline". Binary {0.0, 1.0}.
- All novelty features return 0.0 (not novel) when no baseline exists
  (cold-start: we cannot assert novelty without a reference).
- Except dst_ip_is_novel/src_ip_is_novel — these return 0.0 on cold-start
  since we have no baseline to compare against.
- bytes_out_z_score uses safe_z_score; returns 0.0 when std=0.

Cold-start novelty default — Architectural Decision (F02, Option A)
--------------------------------------------------------------------
All novelty features (dst_ip_is_novel, src_ip_is_novel, port_is_novel,
protocol_is_novel) default to 0.0 when baseline is None.

Rationale: novelty is defined as "not in the known set". Without a known
set (baseline), the concept is undefined. Asserting 1.0 (novel) on cold-start
would mean every cold-start event is flagged as having unknown IPs/ports —
which inflates anomaly scores for entities that are simply new rather than
malicious, and would contaminate IF training data if training occurs before
a full baseline is established.

The `baseline_presence` feature group carries the cold-start signal to the
Isolation Forest via has_*_baseline features. The IF learns to interpret
combinations of novelty=0.0 + has_baseline=0.0 as cold-start, not normal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import (
    BaseExtractor,
    binary,
    safe_frequency,
    safe_percentile_rank,
    safe_z_score,
)

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline, NetworkBaseline
    from backend.normalization.models import CanonicalEvent


class NetworkExtractor(BaseExtractor):
    """Network behavior novelty and deviation features."""

    @property
    def group_name(self) -> str:
        return "network"

    @property
    def feature_names(self) -> list[str]:
        return [
            "dst_ip_is_novel",
            "src_ip_is_novel",
            "port_is_novel",
            "protocol_is_novel",
            "port_baseline_frequency",
            "protocol_baseline_frequency",
            "bytes_out_z_score",
            "bytes_out_percentile_rank",
            "unique_dst_ips_baseline",
            "connection_count_baseline",
        ]

    def extract(
        self,
        event: CanonicalEvent,
        baseline: EntityBaseline | None,
    ) -> dict[str, float]:
        net: NetworkBaseline | None = None
        if baseline is not None:
            net = baseline.network

        # ── dst IP novelty ────────────────────────────────────────────────
        # Cold-start default = 0.0 (not novel). See module docstring for the
        # F02 architectural decision rationale.
        dst_novel = 0.0
        if net is not None and event.dst_ip is not None:
            dst_novel = binary(event.dst_ip not in net.unique_dst_ips)

        # ── src IP novelty ─────────────────────────────────────────────────
        # Cold-start default = 0.0 (not novel) — same rationale as dst_novel.
        src_novel = 0.0
        if net is not None and event.src_ip is not None:
            src_novel = binary(event.src_ip not in net.unique_src_ips)

        # ── Port novelty ───────────────────────────────────────────────────
        port_novel = 0.0
        port_freq = 0.0
        if net is not None and event.port is not None:
            port_key = str(event.port)
            port_novel = binary(port_key not in net.port_distribution)
            port_freq = safe_frequency(event.port, net.port_distribution, lower=False)

        # ── Protocol novelty ───────────────────────────────────────────────
        proto_novel = 0.0
        proto_freq = 0.0
        if net is not None and event.protocol is not None:
            proto_novel = binary(
                event.protocol.lower() not in {k.lower() for k in net.protocol_distribution}
            )
            proto_freq = safe_frequency(event.protocol, net.protocol_distribution)

        # ── bytes_out deviation ────────────────────────────────────────────
        bytes_z = 0.0
        bytes_pct = 0.0
        if net is not None and event.bytes_out is not None and net.bytes_out_stats is not None:
            stats = net.bytes_out_stats
            bytes_z = safe_z_score(float(event.bytes_out), stats.mean, stats.std)
            bytes_pct = safe_percentile_rank(
                float(event.bytes_out),
                stats.p25,
                stats.p50,
                stats.p75,
                stats.p95,
            )

        # ── Summary counts from baseline ───────────────────────────────────
        unique_dst_count = 0.0
        conn_count = 0.0
        if net is not None:
            unique_dst_count = float(len(net.unique_dst_ips))
            conn_count = float(net.connection_count)

        return {
            "dst_ip_is_novel": dst_novel,
            "src_ip_is_novel": src_novel,
            "port_is_novel": port_novel,
            "protocol_is_novel": proto_novel,
            "port_baseline_frequency": port_freq,
            "protocol_baseline_frequency": proto_freq,
            "bytes_out_z_score": bytes_z,
            "bytes_out_percentile_rank": bytes_pct,
            "unique_dst_ips_baseline": unique_dst_count,
            "connection_count_baseline": conn_count,
        }
