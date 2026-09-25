"""Record anomaly detections: the one command that writes ``anomaly_detections``.

Usage::

    python -m aicore_api.risk.cli record --organization acme \\
        [--baseline 14d] [--observation 24h] [--as-of 2026-09-25T10:00:00+00:00]

It analyses every agent of one organization over one pair of windows and inserts each
detection, deduplicated by fingerprint, then prints a JSON summary. Running it twice with
the same ``--as-of`` records nothing the second time.

Why a command and not an endpoint: the HTTP API is read-only, so no client can submit —
or spoof — a detection, a risk level or evidence. Recording is an operator's decision
(typically a scheduled job), made with database access, like Phase 2's provisioning
commands. It performs no response of any kind: it does not alert, suspend, block, revoke
or open an incident. It records what the engine found, and that is all.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from aicore_api.core.domain_errors import NotFoundError
from aicore_api.core.risk import (
    DEFAULT_BASELINE_WINDOW,
    DEFAULT_OBSERVATION_WINDOW,
    BaselineWindow,
    ObservationWindow,
    RiskError,
    resolve_analysis_windows,
)
from aicore_api.db.models.organization import Organization
from aicore_api.db.repositories.anomaly_detections import AnomalyDetectionRepository
from aicore_api.db.repositories.organizations import OrganizationRepository
from aicore_api.db.repositories.risk_history import RiskHistoryRepository
from aicore_api.db.session import get_session_factory
from aicore_api.risk.service import DetectionRecorder, RecordSummary, RiskAnalysisService

__all__ = ["build_parser", "main", "summary_document"]


def _resolve_organization(session: Session, identifier: str) -> Organization:
    """A tenant by UUID or by slug, or :class:`NotFoundError`."""
    repository = OrganizationRepository(session)
    try:
        organization_id = uuid.UUID(identifier)
    except ValueError:
        organization = repository.find_by_slug(identifier)
        if organization is None:
            raise NotFoundError(f"no organization with slug {identifier!r}") from None
        return organization
    return repository.get(organization_id)


def _as_of(value: str) -> datetime:
    """Parse ``--as-of``; the window rules (aware, whole hour, not future) apply later."""
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an ISO-8601 instant: {value!r}") from exc


def summary_document(summary: RecordSummary) -> dict[str, object]:
    """The run's summary as the JSON the command prints."""
    windows = summary.windows
    return {
        "organization_id": str(summary.organization_id),
        "baseline": {
            "window": windows.baseline.value,
            "start": windows.baseline_start.isoformat(),
            "end": windows.baseline_end.isoformat(),
        },
        "observation": {
            "window": windows.observation.value,
            "start": windows.observation_start.isoformat(),
            "end": windows.observation_end.isoformat(),
        },
        "agents_analyzed": summary.agents_analyzed,
        "insufficient_history": summary.insufficient_history,
        "anomalous": summary.anomalous,
        "detections_found": summary.detections_found,
        "detections_recorded": summary.detections_recorded,
        "truncated": summary.truncated,
    }


def _cmd_record(
    args: argparse.Namespace,
    *,
    session_factory: Callable[[], Session],
    now: datetime,
) -> int:
    with session_factory() as session:
        organization = _resolve_organization(session, args.organization)
        windows = resolve_analysis_windows(
            baseline=args.baseline, observation=args.observation, as_of=args.as_of, now=now
        )
        history = RiskHistoryRepository(session, organization.id)
        store = AnomalyDetectionRepository(session, organization.id)
        summary = DetectionRecorder(RiskAnalysisService(history), store).record(windows)
        session.commit()
    print(json.dumps(summary_document(summary), sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m aicore_api.risk.cli",
        description=(
            "Record the anomaly detections of one organization. Analytical only: this "
            "command never alerts, blocks, suspends, revokes or opens an incident."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record", help="analyse every agent and record detections")
    record.add_argument("--organization", required=True, help="organization slug or UUID")
    record.add_argument(
        "--baseline",
        choices=[window.value for window in BaselineWindow],
        default=DEFAULT_BASELINE_WINDOW.value,
    )
    record.add_argument(
        "--observation",
        choices=[window.value for window in ObservationWindow],
        default=DEFAULT_OBSERVATION_WINDOW.value,
    )
    record.add_argument(
        "--as-of",
        type=_as_of,
        default=None,
        help="a whole UTC hour, timezone-aware; defaults to the start of the current hour",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    session_factory: Callable[[], Session] | None = None,
    now: datetime | None = None,
) -> int:
    """Run the command. Returns a process exit code (0 ok, 1 not found, 2 invalid)."""
    args = build_parser().parse_args(argv)
    factory = session_factory if session_factory is not None else get_session_factory()
    clock = now if now is not None else datetime.now(UTC)
    try:
        return _cmd_record(args, session_factory=factory, now=clock)
    except NotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except RiskError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised as a process
    raise SystemExit(main())
