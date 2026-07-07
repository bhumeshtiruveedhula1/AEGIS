"""
backend.features.writer — Feature Vector Writer
================================================
Module 2.2 — Behavioral Feature Engine

Persists FeatureRecord objects to JSONL output files.

Output Format
-------------
One JSON object per line (JSONL). Each line is a complete FeatureRecord.
Files are UTF-8, LF line endings.

Output file naming: features_<run_id>.jsonl
A separate pipeline_report.json summarises each run.

Design
------
- Writer is a context manager for safe file lifecycle management.
- Supports streaming writes — no in-memory accumulation.
- Human-readable JSON (2-space indent) for the report; compact JSONL for vectors.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from backend.core.config import get_settings
from backend.features.exceptions import FeatureWriterError
from backend.features.models import FeaturePipelineReport, FeatureRecord

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)

_DEFAULT_FEATURE_SUBDIR = "features"


class FeatureVectorWriter:
    """
    Streams FeatureRecord objects to a JSONL file.

    Usage
    -----
        with FeatureVectorWriter() as writer:
            for record in records:
                writer.write(record)
        report = writer.report()

    Parameters
    ----------
    output_dir   : Directory to write feature files. Defaults to
                   settings.data_dir / "features".
    run_id       : Optional run ID to include in file names.
                   Defaults to a generated UUID.
    """

    def __init__(
        self,
        output_dir: Path | None = None,
        *,
        run_id: str | None = None,
    ) -> None:
        settings = get_settings()
        self._output_dir = output_dir or (settings.data_dir / _DEFAULT_FEATURE_SUBDIR)
        from backend.shared.utils.id_utils import generate_id
        self._run_id = run_id or generate_id()
        self._records_written = 0
        self._file: object = None
        self._output_path: Path | None = None
        self._started_at: datetime = datetime.now(UTC)

    def __enter__(self) -> "FeatureVectorWriter":
        self._open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._close()

    def write(self, record: FeatureRecord) -> None:
        """
        Write one FeatureRecord to the output JSONL file.

        Raises
        ------
        FeatureWriterError if the file is not open.
        """
        if self._file is None:
            msg = "FeatureVectorWriter is not open. Use as a context manager."
            raise FeatureWriterError(msg)
        try:
            line = record.model_dump_json() + "\n"
            self._file.write(line)  # type: ignore[union-attr]
            self._records_written += 1
        except Exception as exc:
            msg = f"Failed to write FeatureRecord: {exc}"
            raise FeatureWriterError(msg) from exc

    def write_batch(self, records: list[FeatureRecord]) -> int:
        """Write multiple records. Returns count written."""
        for record in records:
            self.write(record)
        return len(records)

    def write_report(self, report: FeaturePipelineReport) -> Path:
        """
        Write the pipeline report as a human-readable JSON file.

        Returns the path to the written report file.
        """
        report_path = self._output_dir / "pipeline_report.json"
        try:
            report_path.write_text(
                json.dumps(
                    json.loads(report.model_dump_json()),
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            msg = f"Failed to write pipeline report: {exc}"
            raise FeatureWriterError(msg) from exc
        logger.info("feature_report_written", path=str(report_path))
        return report_path

    def report(self) -> FeaturePipelineReport:
        """Return a report summarising this write session."""
        return FeaturePipelineReport(
            run_id=self._run_id,
            started_at=self._started_at,
            completed_at=datetime.now(UTC),
            feature_records_written=self._records_written,
            output_file=str(self._output_path) if self._output_path else None,
        )

    @property
    def output_path(self) -> Path | None:
        """Path to the current output file."""
        return self._output_path

    @property
    def records_written(self) -> int:
        """Count of records written in this session."""
        return self._records_written

    # ── Private ─────────────────────────────────────────────────────────────

    def _open(self) -> None:
        """Open the output JSONL file for writing."""
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            msg = f"Cannot create feature output directory {self._output_dir}: {exc}"
            raise FeatureWriterError(msg) from exc

        self._output_path = self._output_dir / f"features_{self._run_id}.jsonl"
        try:
            self._file = self._output_path.open("w", encoding="utf-8", newline="\n")
        except Exception as exc:
            msg = f"Cannot open feature output file {self._output_path}: {exc}"
            raise FeatureWriterError(msg) from exc

        logger.info("feature_writer_opened", path=str(self._output_path))

    def _close(self) -> None:
        """Flush and close the output file."""
        if self._file is not None:
            try:
                self._file.close()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass
            self._file = None
            logger.info(
                "feature_writer_closed",
                records=self._records_written,
                path=str(self._output_path),
            )
