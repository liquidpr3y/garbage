"""Telemetry collectors.

Two sources, deliberately different in kind: the guest ships Sysmon to the
lab's existing Elastic cluster (we query it back rather than standing up a
parallel logging stack), and the host captures packets off the sandbox
network. Neither collector runs inside the sample's process or on its output.
"""
