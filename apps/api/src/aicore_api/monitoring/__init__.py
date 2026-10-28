"""The monitoring subsystem: measurement over the record, and nothing beyond it.

Phase 9's subject is *counting*. Phase 8 built the durable record of what happened; this
package turns it into the questions an operator actually asks — what is running, how often,
what is being refused, what is failing, what changed, and is any of it rising or falling —
and it answers them with arithmetic over that record rather than with a second stream of
facts that could disagree with it.

Three modules, and the split is the design:

- :mod:`aicore_api.core.monitoring` is the **vocabulary**: the windows this build serves,
  the counter definitions, the bucket arithmetic and the rate calculation. Pure — no
  database, no clock, no request.
- :mod:`aicore_api.db.repositories.monitoring` is the **aggregation**: tenant-scoped,
  window-bounded SQL over ``aicore.audit_events``, generated from those counter definitions.
- :mod:`aicore_api.monitoring.service` is the **assembly**: the numbers the API publishes,
  with the zeros filled in and the totals derived, as typed records the tests can check
  without HTTP.

What this package is not, and will not become: an anomaly detector, a risk engine, an
incident manager or an alerting system. There is no baseline, no threshold, no score, no
severity and no notion of normal here — a spike is a bigger number, and nothing more is
claimed about it. Those are different subjects with different vocabulary and their own
phases, and none of them gets a foothold by extending this one: monitoring reads the trail,
and it holds no object that could write to it, change a policy, suspend an agent or run an
action.
"""

from __future__ import annotations

from aicore_api.monitoring.service import (
    ActionActivity,
    AgentActivity,
    AgentActivityPage,
    MonitoringService,
    PolicyActivity,
    Summary,
    TrendBucket,
)

__all__ = [
    "ActionActivity",
    "AgentActivity",
    "AgentActivityPage",
    "MonitoringService",
    "PolicyActivity",
    "Summary",
    "TrendBucket",
]
