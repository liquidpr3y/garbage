"""Dynamic analysis: detonating a sample somewhere that is not this machine.

The single structural invariant of this package: there is no way to execute a
sample on the host. `DetonationTarget` has no localhost implementation, none
may be added, and `tests/test_sandbox_safety.py` fails the build if one
appears. Execution is only reachable through a target that is definitionally a
separate machine.
"""
