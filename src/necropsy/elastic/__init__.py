"""The lab's existing Elastic cluster.

Necropsy does not stand up a logging stack. The guest ships Sysmon through the
Elastic Agent that is already there, and this package reads it back for
correlation. Phase 4 adds the findings mirror in the other direction.

Everything here degrades: an unreachable cluster costs telemetry correlation,
never a detonation and never a finding already in SQLite.
"""

from necropsy.elastic.client import ElasticClient, ElasticError, ElasticUnavailable

__all__ = ["ElasticClient", "ElasticError", "ElasticUnavailable"]
