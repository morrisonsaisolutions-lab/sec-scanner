class SecScannerError(Exception):
    """Expected failure the CLI can report without a traceback."""


class AdvisoryError(SecScannerError):
    """The advisory bundle is missing, unsigned, stale-dated, or not usable."""
