"""The anomaly and risk service: aggregates in, explainable analyses out.

Two small classes, deliberately separate:

- :class:`RiskAnalysisService` computes. It asks
  :class:`~aicore_api.db.repositories.risk_history.RiskHistoryRepository` for one page of
  bounded per-agent aggregates and hands each to the pure engine
  (:func:`aicore_api.core.risk.analyze_agent`). It writes nothing, anywhere.
- :class:`DetectionRecorder` records. It pages through an analysis and inserts each
  detection into ``anomaly_detections`` through
  :class:`~aicore_api.db.repositories.anomaly_detections.AnomalyDetectionRepository`.
  It is used by the operator command (``python -m aicore_api.risk.cli``), never by an HTTP
  route: the API is read-only.

Neither class can do anything *about* a detection. There is no import here of the firewall,
the policy engine, the execution layer, the agent registry, the permission model or the
audit writer — ``tests/test_risk_read_only.py`` asserts that — so there is no code path from
"this agent looks unusual" to suspending it, blocking it, revoking a grant, changing a
policy, opening an incident or sending an alert. A detection is information for a person.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from aicore_api.core.risk import AgentAnalysis, AnalysisStatus, AnalysisWindows, analyze_agent
from aicore_api.db.repositories.anomaly_detections import (
    AnomalyDetectionRepository,
    detection_records,
)
from aicore_api.db.repositories.risk_history import MAX_ANALYSIS_PAGE, RiskHistoryRepository

__all__ = [
    "MAX_RECORDED_AGENTS",
    "AnalysisPage",
    "DetectionRecorder",
    "RecordSummary",
    "RiskAnalysisService",
]

#: The most agents one recording run will analyse. A backstop, not a page size: a run that
#: reaches it says so in its summary (``truncated``) rather than silently stopping short.
MAX_RECORDED_AGENTS = 10_000


@dataclass(frozen=True, slots=True)
class AnalysisPage:
    """One page of analyses, and the total behind it when it was asked for."""

    items: tuple[AgentAnalysis, ...]
    total: int | None


@dataclass(frozen=True, slots=True)
class RecordSummary:
    """What one recording run did — the CLI prints this, and nothing else."""

    organization_id: uuid.UUID
    windows: AnalysisWindows
    agents_analyzed: int
    insufficient_history: int
    anomalous: int
    detections_found: int
    detections_recorded: int
    truncated: bool


class RiskAnalysisService:
    """Analyse one organization's agents over one pair of windows. Read-only."""

    def __init__(self, history: RiskHistoryRepository) -> None:
        self._history = history

    @property
    def organization_id(self) -> uuid.UUID:
        return self._history.organization_id

    def analyze(
        self,
        windows: AnalysisWindows,
        *,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
        total: bool = False,
    ) -> AnalysisPage:
        """One page of agents, each analysed. Seven statements at most, whatever the page.

        The page is chosen first (agents with a request in the analysis, by identifier),
        then profiled in six aggregate statements covering the whole page, then assessed in
        Python — over aggregates only, so the Python cost is per agent, not per event.
        """
        agent_ids = self._history.agent_page(windows, limit=limit, offset=offset, agent_id=agent_id)
        profiles = self._history.profiles(windows, agent_ids)
        analyses = tuple(analyze_agent(profile, windows) for profile in profiles)
        counted = self._history.count_agents(windows, agent_id=agent_id) if total else None
        return AnalysisPage(items=analyses, total=counted)


class DetectionRecorder:
    """Record every detection of one analysis. Insert-only and idempotent."""

    def __init__(self, analysis: RiskAnalysisService, store: AnomalyDetectionRepository) -> None:
        if analysis.organization_id != store.organization_id:
            raise ValueError("the analysis and the store must belong to the same organization")
        self._analysis = analysis
        self._store = store

    def record(
        self,
        windows: AnalysisWindows,
        *,
        page_size: int = MAX_ANALYSIS_PAGE,
        max_agents: int = MAX_RECORDED_AGENTS,
    ) -> RecordSummary:
        """Analyse every agent (page by page) and insert what is anomalous.

        Re-running with the same windows inserts nothing new: each detection's fingerprint
        is a function of what was assessed, and the table refuses a second copy.
        """
        analyzed = insufficient = anomalous = found = recorded = 0
        offset = 0
        truncated = False
        while True:
            if offset >= max_agents:
                truncated = True
                break
            size = min(page_size, max_agents - offset)
            page = self._analysis.analyze(windows, limit=size, offset=offset)
            analyses: Sequence[AgentAnalysis] = page.items
            records = []
            for item in analyses:
                analyzed += 1
                if item.status is AnalysisStatus.INSUFFICIENT_HISTORY:
                    insufficient += 1
                elif item.detections:
                    anomalous += 1
                records.extend(detection_records(item, windows))
            found += len(records)
            recorded += len(self._store.record(records))
            if len(analyses) < size:
                break
            offset += size
        return RecordSummary(
            organization_id=self._store.organization_id,
            windows=windows,
            agents_analyzed=analyzed,
            insufficient_history=insufficient,
            anomalous=anomalous,
            detections_found=found,
            detections_recorded=recorded,
            truncated=truncated,
        )
