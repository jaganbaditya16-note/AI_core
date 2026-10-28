"""Phase 10: the anomaly and risk engine's service layer and operator command.

The rules live in :mod:`aicore_api.core.risk` (pure, no I/O); the queries in
:mod:`aicore_api.db.repositories.risk_history` and
:mod:`aicore_api.db.repositories.anomaly_detections`; the orchestration here. Analytical
only: nothing in this package authorizes, blocks, executes, suspends, revokes, alerts or
opens an incident. See ``docs/risk.md``.
"""
