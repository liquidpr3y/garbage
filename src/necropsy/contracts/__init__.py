"""The plug-in seam.

Everything in this package is the *reference definition* of vocabulary shared
between Necropsy and the pentest GUI backend. Two rules, both load-bearing:

1. Stdlib + pydantic only. The host must be able to depend on these three
   modules without inheriting SQLAlchemy, RQ, LIEF or anything else of ours.
2. No business logic. Types and protocols only.

When the host adopts them, extract this package into a small shared
``pentestgui-contracts`` distribution that both sides depend on. That is the
right moment to extract -- not before. See docs/HOST_INTEGRATION.md.
"""

from necropsy.contracts.events import Event, EventType
from necropsy.contracts.host import HostServices, RiskPolicy
from necropsy.contracts.risk import ActionProposal, RiskFactor, RiskScore, score_factors

__all__ = [
    "ActionProposal",
    "Event",
    "EventType",
    "HostServices",
    "RiskFactor",
    "RiskPolicy",
    "RiskScore",
    "score_factors",
]
