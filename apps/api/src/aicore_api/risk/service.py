"""The risk service: resolve the windows, read two frames, assess, and record if asked.

This is the layer between the arithmetic and the request, and it is deliberately thin,
because everything interesting is either below it (the engine, the repository) or above it
(the route and its schemas). What it owns is the *sequence*:

1. **Two windows, decided once.** The observation window comes from Phase 9's resolver; the
   baseline is anchored so it ends where the observation begins. Nothing here reads a clock
   — the route passes the instant it read, which is the same instant the observation window
   was resolved against, so every number in one response describes one moment.
2. **Two frames per agent, from three reads.** The repository answers each window from one
   statement per question (hourly counts, actions, resources), for the whole page of agents
   at once, so assessing fifty agents is six queries rather than three hundred.
3. **Assessment, then optionally a record.** An assessment is pure computation over those
   frames. Recording it writes one append-only row keyed by the assessment's identity, and
   a repeated request returns the row that exists instead of writing a second.

**What this service cannot do.** It holds no authorization decision, no policy, no executor
and no audit writer: it cannot change a permission, alter a policy, append to the trail, run
an action or suspend an agent, because none of those objects is in scope here. The only
write it can reach is :meth:`DetectionRepository.record`, which writes to one table and can
write nothing else.

**What it stores, and what a client can influence.** The evidence and factors a record
carries are rendered by the schema models — the same ones the response uses — from values
the engine computed. A request contributes exactly two things: which agent, and which
interval. Every threshold, level, mean, bound, identifier and count is server-side.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from aicore_api.core.domain_errors import NotFoundError
from aicore_api.core.monitoring import ResolvedWindow
from aicore_api.core.risk import (
    DEFAULT_PARAMETERS,
    ActivityFrame,
    AssessmentStatus,
    Baseline,
    DetectionParameters,
)
from aicore_api.db.models.agent import Agent
from aicore_api.db.models.anomaly_detection import AnomalyDetection
from aicore_api.db.repositories.agents import AgentRepository
from aicore_api.db.repositories.risk import DetectionDraft, DetectionRepository, RiskRepository
from aicore_api.risk.engine import Assessment, assess_agent
from aicore_api.schemas.risk import (
    RiskBaselineRead,
    RiskObservationRead,
    RiskParametersRead,
    evidence_document,
    factors_document,
)

__all__ = ["AssessmentBundle", "RiskService"]


@dataclass(frozen=True, slots=True)
class AssessmentBundle:
    """An assessment and everything it was computed from.

    Kept together because a response states the observation and the baseline alongside the
    conclusion, and a record stores them: splitting the assessment from its frames would
    mean recomputing or re-reading one of them to say what it was about.
    """

    assessment: Assessment
    observation: ActivityFrame
    baseline: ActivityFrame
    baseline_window: Baseline
    parameters: DetectionParameters

    # ── The schema-facing views of the two frames ────────────────────────────

    def observation_read(self) -> RiskObservationRead:
        """The observation frame as the response and the stored evidence state it."""
        return RiskObservationRead.from_frame(self.observation)

    def baseline_read(self) -> RiskBaselineRead:
        """The baseline frame as the response and the stored evidence state it."""
        return RiskBaselineRead.from_frame(self.baseline, window=self.baseline_window.name)

    def parameters_read(self) -> RiskParametersRead:
        """The thresholds this assessment was computed with."""
        return RiskParametersRead.from_parameters(self.parameters)


class RiskService:
    """One organization's risk analysis, over one session.

    Constructed per request with the organization the authorized context resolved — never a
    value from the query string, the body or a header — so every statement the three
    repositories can build carries that tenant.
    """

    def __init__(
        self,
        *,
        risk: RiskRepository,
        detections: DetectionRepository,
        agents: AgentRepository,
        parameters: DetectionParameters = DEFAULT_PARAMETERS,
    ) -> None:
        self._risk = risk
        self._detections = detections
        self._agents = agents
        self._parameters = parameters

    @property
    def parameters(self) -> DetectionParameters:
        """The thresholds in force for this service."""
        return self._parameters

    # ── Assessing ────────────────────────────────────────────────────────────

    def assess_agent(
        self, *, agent_id: uuid.UUID, observation: ResolvedWindow, baseline_window: Baseline
    ) -> AssessmentBundle:
        """Assess one registered agent, or refuse if this organization has no such agent.

        "No such agent" and "another organization's agent" are the same answer — the
        registry lookup is tenant-scoped, so an identifier from elsewhere simply has no row
        here, and this method does not learn that it exists somewhere else.
        """
        agent = self._agents.find(agent_id)
        if agent is None:
            raise NotFoundError(f"agent {agent_id} was not found")
        return self._assess([agent], observation=observation, baseline_window=baseline_window)[0]

    def assess_page(
        self,
        *,
        observation: ResolvedWindow,
        baseline_window: Baseline,
        limit: int,
        offset: int,
    ) -> tuple[list[AssessmentBundle], int]:
        """Assess a page of the registry, newest registration first.

        The population is the registry rather than the trail, and that choice matters: an
        agent that was active last week and silent since is the case a drop in activity is
        about, and an agent with no activity at all is still assessed — with empty frames
        that say "nothing happened in this window" rather than with silence. Returns the
        page and the total number of registered agents behind it.
        """
        agents = self._agents.page(limit=limit, offset=offset)
        total = self._agents.count()
        if not agents:
            return [], total
        return (
            self._assess(agents, observation=observation, baseline_window=baseline_window),
            total,
        )

    def _assess(
        self,
        agents: Sequence[Agent],
        *,
        observation: ResolvedWindow,
        baseline_window: Baseline,
    ) -> list[AssessmentBundle]:
        """Build both frames for every agent in one batch, then assess each."""
        agent_ids = [agent.id for agent in agents]
        observed = self._risk.activity(
            start=observation.start, end=observation.end, agent_ids=agent_ids
        )
        historical = self._risk.activity(
            start=baseline_window.start, end=baseline_window.end, agent_ids=agent_ids
        )
        bundles: list[AssessmentBundle] = []
        for agent_id in agent_ids:
            observation_frame = observed[agent_id]
            baseline_frame = historical[agent_id]
            bundles.append(
                AssessmentBundle(
                    assessment=assess_agent(
                        agent_id=agent_id,
                        observation=observation_frame,
                        baseline=baseline_frame,
                        parameters=self._parameters,
                    ),
                    observation=observation_frame,
                    baseline=baseline_frame,
                    baseline_window=baseline_window,
                    parameters=self._parameters,
                )
            )
        return bundles

    # ── Recording ────────────────────────────────────────────────────────────

    def record(self, bundle: AssessmentBundle) -> tuple[AnomalyDetection, bool]:
        """Record an assessment, or return the identical record that already exists.

        The rows this writes are the phase's only writes, and the table it writes them to
        holds findings and nothing else. The response says which happened — recorded now, or
        already recorded — because "the same window assessed twice" is a fact worth stating
        rather than a duplicate worth hiding.
        """
        assessment = bundle.assessment
        draft = DetectionDraft(
            entity_type=assessment.entity_type,
            entity_id=assessment.entity_id,
            status=assessment.status.value,
            anomaly=assessment.anomaly,
            risk_level=assessment.risk_level.value,
            detection_type=(
                None if assessment.detection_type is None else assessment.detection_type.value
            ),
            observation_start=bundle.observation.start,
            observation_end=bundle.observation.end,
            baseline_start=bundle.baseline.start,
            baseline_end=bundle.baseline.end,
            baseline_window=bundle.baseline_window.name.value,
            evidence=evidence_document(
                observation=bundle.observation_read(),
                baseline=bundle.baseline_read(),
                parameters=bundle.parameters_read(),
                assessment=assessment,
            ),
            factors=factors_document(assessment),
        )
        return self._detections.record(draft)

    # ── Reading what was recorded ────────────────────────────────────────────

    def detections(
        self,
        *,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
        detection_type: str | None = None,
        risk_level: str | None = None,
        status: AssessmentStatus | None = None,
    ) -> list[AnomalyDetection]:
        """A page of recorded assessments, newest first.

        An ``agent_id`` filter is not an existence check: an identifier this organization has
        no records for returns an empty page, exactly as an unknown one does.
        """
        return self._detections.page(
            limit=limit,
            offset=offset,
            entity_id=agent_id,
            detection_type=detection_type,
            risk_level=risk_level,
            status=None if status is None else status.value,
        )

    def detection_count(
        self,
        *,
        agent_id: uuid.UUID | None = None,
        detection_type: str | None = None,
        risk_level: str | None = None,
        status: AssessmentStatus | None = None,
    ) -> int:
        """How many records match the same filters, for an opt-in ``?total=true``."""
        return self._detections.count(
            entity_id=agent_id,
            detection_type=detection_type,
            risk_level=risk_level,
            status=None if status is None else status.value,
        )

    def detection(self, detection_id: uuid.UUID) -> AnomalyDetection:
        """One recorded assessment, or :class:`NotFoundError`.

        A foreign identifier and an unknown one take the same path: the lookup is
        tenant-scoped, so both find nothing and neither can tell the caller which it was.
        """
        recorded = self._detections.find(detection_id)
        if recorded is None:
            raise NotFoundError(f"detection {detection_id} was not found")
        return recorded
