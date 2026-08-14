"""ClaimFence: deterministic linting for evidence-bound documentation claims."""

__version__ = "0.3.0"

from .models import Finding, ScanResult, Severity
from .scanner import scan_paths

__all__ = ["Finding", "ScanResult", "Severity", "__version__", "scan_paths"]
