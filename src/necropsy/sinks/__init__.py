from necropsy.sinks.base import FindingSink, NullSink, get_sink, set_sink
from necropsy.sinks.elastic import ElasticFindingSink, install_if_configured

__all__ = [
    "ElasticFindingSink",
    "FindingSink",
    "NullSink",
    "get_sink",
    "install_if_configured",
    "set_sink",
]
