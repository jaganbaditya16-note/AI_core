"""The risk subsystem: a comparison between two windows of the record, and nothing beyond it.

Phase 10's subject is *deviation*. Phase 8 recorded what happened, Phase 9 counted it, and
this package asks a question neither of them asks: is what this agent did in this window
different from what it usually does — and if so, by how much, measured against what, and
from how many observations? The answer is arithmetic over the same trail, with the baseline
and the observation stated in the response, and it is a *finding*, not a verdict: the level
it reports describes the evidence, never the entity.

Three modules, and the split is the design:

- :mod:`aicore_api.core.risk` is the **vocabulary**: entity and detection types, the risk
  levels and the rule table that maps factors to them, the named baselines, the detection
  parameters, and the statistics (mean, population spread, bounds). Pure — no database, no
  clock, no request, no configuration lookup.
- :mod:`aicore_api.risk.engine` is the **comparison**: one agent's observation frame and
  baseline frame in, one explainable assessment out. Also pure: the same two frames always
  produce the same assessment, which is what makes the numbers in a test checkable.
- :mod:`aicore_api.risk.service` is the **assembly**: resolve two windows, read the frames
  from the repository, assess, and record the result if the caller asked for a record.

What this package is not, and will not become: an authorization engine, a firewall, a policy
evaluator, an incident manager, an alerting system, a response mechanism or a source of
truth about intent. It cannot authorize or deny an action, cannot change a policy, cannot
suspend an agent, cannot append to the audit trail, and cannot run anything. Every statement
it makes about an entity is a statement about a measurement, and the phrase it will never
produce is "this agent is compromised" — only "this measurement deviated from that baseline".
"""

from __future__ import annotations

from aicore_api.risk.engine import Assessment, Dimension, Factor, FactorItem, FactorItemKind
from aicore_api.risk.service import AssessmentBundle, RiskService

__all__ = [
    "Assessment",
    "AssessmentBundle",
    "Dimension",
    "Factor",
    "FactorItem",
    "FactorItemKind",
    "RiskService",
]
