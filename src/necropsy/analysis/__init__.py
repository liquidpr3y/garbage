"""Static analysis producers.

Every module here turns bytes into `Finding` rows. None of them execute the
sample; that is structurally impossible from this package -- there is no
detonation target here and no subprocess is ever handed the sample as an
executable, only as an argument to a read-only analyser.
"""
