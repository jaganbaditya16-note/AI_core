"""The anomaly detection store: record once, read many, never rewrite.

:class:`AnomalyDetectionRepository` is the only code that touches
``aicore.anomaly_detections``. It can insert findings (deduplicated by the database) and
read them back, tenant-scoped. It has no ``update`` and no ``delete``: the table's trigger
refuses ``UPDATE`` anyway, and a finding has no lifecycle to move through — it is not an
incident, and there is nothing to acknowledge, assign or close.

Rows are built from :class:`~aicore_api.core.risk.Detection` values by
:func:`detection_records`, never from request input: there is no path by which a caller
could hand this repository a risk level, a baseline or evidence of their own.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select
from sqlalchemy.dialects.postgresql import insert

from aicore_api.core.risk import (
    DETECTION_SCHEMA_VERSION,
    RISK_ENGINE_VERSION,
    AgentAnalysis,
    AnalysisStatus,
    AnalysisWindows,
    AnomalyState,
    DetectionType,
    EntityType,
    RiskLevel,
    detection_fingerprint,
)
from aicore_api.db.models.anomaly_detection import AnomalyDetection
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["AnomalyDetectionRepository", "DetectionRecord", "detection_records"]

_UNIQUE = "uq_anomaly_detections_organization_id_fingerprint"


@dataclass(frozen=True, slots=True)
class DetectionRecord:
    """One detection, shaped for the table. Built by :func:`detection_records` only."""

    entity_type: EntityType
    entity_id: uuid.UUID
    detection_type: DetectionType
    risk_level: RiskLevel
    windows: AnalysisWindows
    evidence: Mapping[str, Any]
    risk_factors: Sequence[Mapping[str, Any]]
    fingerprint: str


def _plain(value: Mapping[str, Any]) -> dict[str, Any]:
    """A read-only evidence mapping as plain JSON data (mapping proxies are not JSON)."""
    plain: dict[str, Any] = json.loads(json.dumps(dict(value), default=dict))
    return plain


def detection_records(analysis: AgentAnalysis, windows: AnalysisWindows) -> list[DetectionRecord]:
    """Every detection in ``analysis`` as a row to record. Empty when nothing is anomalous.

    An entity with insufficient history, or with nothing unusual, yields nothing: the table
    holds anomalies, and "we could not tell" is never stored as though it were a finding.
    """
    if analysis.status is not AnalysisStatus.ANALYZED:
        return []
    return [
        DetectionRecord(
            entity_type=EntityType.AGENT,
            entity_id=analysis.agent_id,
            detection_type=detection.detection_type,
            risk_level=detection.risk_level,
            windows=windows,
            evidence=_plain(detection.evidence),
            risk_factors=[factor.as_dict() for factor in detection.risk_factors],
            fingerprint=detection_fingerprint(
                entity_type=EntityType.AGENT,
                entity_id=analysis.agent_id,
                detection_type=detection.detection_type,
                windows=windows,
            ),
        )
        for detection in analysis.detections
    ]


class AnomalyDetectionRepository(OrganizationScopedRepository):
    """Tenant-scoped access to recorded detections."""

    # ── Write: insert-only, deduplicated by the database ─────────────────────

    def record(self, records: Sequence[DetectionRecord]) -> list[uuid.UUID]:
        """Insert ``records``; return the identifiers of the rows that were new.

        ``ON CONFLICT (organization_id, fingerprint) DO NOTHING``: a finding already
        recorded — by an earlier run, or a concurrent one — is skipped, not updated, so
        recording is idempotent and the first recording is the one that stands.
        """
        if not records:
            return []
        rows = [
            {
                "organization_id": self.organization_id,
                "schema_version": DETECTION_SCHEMA_VERSION,
                "engine_version": RISK_ENGINE_VERSION,
                "entity_type": record.entity_type.value,
                "entity_id": record.entity_id,
                "detection_type": record.detection_type.value,
                "analysis_status": AnalysisStatus.ANALYZED.value,
                "anomaly_state": AnomalyState.ANOMALOUS.value,
                "risk_level": record.risk_level.value,
                "baseline_window": record.windows.baseline.value,
                "observation_window": record.windows.observation.value,
                "baseline_start": record.windows.baseline_start,
                "baseline_end": record.windows.baseline_end,
                "observation_start": record.windows.observation_start,
                "observation_end": record.windows.observation_end,
                "evidence": dict(record.evidence),
                "risk_factors": [dict(factor) for factor in record.risk_factors],
                "fingerprint": record.fingerprint,
            }
            for record in records
        ]
        statement = (
            insert(AnomalyDetection)
            .values(rows)
            .on_conflict_do_nothing(constraint=_UNIQUE)
            .returning(AnomalyDetection.id)
        )
        return [row[0] for row in self.execute(statement).all()]

    # ── Read ─────────────────────────────────────────────────────────────────

    def _filtered(
        self,
        statement: Select[Any],
        *,
        agent_id: uuid.UUID | None,
        detection_type: DetectionType | None,
        risk_level: RiskLevel | None,
    ) -> Select[Any]:
        if agent_id is not None:
            statement = statement.where(
                AnomalyDetection.entity_type == EntityType.AGENT.value,
                AnomalyDetection.entity_id == agent_id,
            )
        if detection_type is not None:
            statement = statement.where(AnomalyDetection.detection_type == detection_type.value)
        if risk_level is not None:
            statement = statement.where(AnomalyDetection.risk_level == risk_level.value)
        return statement

    def list(
        self,
        *,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
        detection_type: DetectionType | None = None,
        risk_level: RiskLevel | None = None,
    ) -> list[AnomalyDetection]:
        """Recorded detections, newest first; ties broken by identifier so pages are total."""
        statement = self._filtered(
            self._scoped(AnomalyDetection),
            agent_id=agent_id,
            detection_type=detection_type,
            risk_level=risk_level,
        )
        statement = (
            statement.order_by(AnomalyDetection.detected_at.desc(), AnomalyDetection.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.execute(statement).scalars().all())

    def count(
        self,
        *,
        agent_id: uuid.UUID | None = None,
        detection_type: DetectionType | None = None,
        risk_level: RiskLevel | None = None,
    ) -> int:
        """How many detections :meth:`list` would page through."""
        statement = self._filtered(
            self._scoped_count(AnomalyDetection),
            agent_id=agent_id,
            detection_type=detection_type,
            risk_level=risk_level,
        )
        return int(self.execute(statement).scalar_one())

    def get(self, detection_id: uuid.UUID) -> AnomalyDetection | None:
        """One detection of this organization, or ``None`` — a foreign row is ``None`` too."""
        statement = self._scoped(AnomalyDetection).where(AnomalyDetection.id == detection_id)
        row: AnomalyDetection | None = self.execute(statement).scalar_one_or_none()
        return row

    def count_all(self) -> int:
        """Every detection this organization has recorded (used by the CLI's summary)."""
        statement = self._scoped_count(AnomalyDetection)
        return int(self.execute(statement).scalar_one())
