"""ClaimFence: deterministic linting for evidence-bound documentation claims."""

from .models import Finding, ScanResult, Severity
from .scanner import scan_paths

__all__ = ["Finding", "ScanResult", "Severity", "scan_paths"]
__version__ = "0.1.0"
