"""MITRE ATT&CK mapping, coverage and Sigma correlation.

Findings arrive already tagged with technique IDs -- Phase 2 and 3 tag at the
producer, where the evidence is. This package does the things that need the
whole case: rolling sub-techniques into parents, laying techniques out on the
matrix, answering what the lab could not have seen, and running Sigma rules
against the telemetry a detonation produced.

ATT&CK data is bundled offline (`data/enterprise.json`, generated from MITRE's
STIX release) so nothing here needs network access at analysis time.
"""

from necropsy.attack.catalogue import Catalogue, get_catalogue

__all__ = ["Catalogue", "get_catalogue"]
