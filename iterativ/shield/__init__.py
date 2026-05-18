"""
iterative.shield
================
Canonical IterativShield™ sub-package.

This sub-package provides the canonical import path:
    from iterativ.shield import guard, redact, scan

It re-exports the three core classes from the parent package modules,
allowing both import styles to work:
    from iterativ import guard          # top-level
    from iterativ.shield import guard   # canonical (preferred)
"""

from iterativ.guard import IterativGuard as guard
from iterativ.redact import IterativRedact as redact
from iterativ.scan import IterativScan as scan

# Also export key types for convenience
from iterativ.guard import GuardResult, RoleContract
from iterativ.redact import (
    RedactResult,
    EntityType,
    FINANCE_ENTITIES,
    STANDARD_ENTITIES,
)
from iterativ.scan import (
    ScanResult,
    ScanFinding,
    ScanType,
    ScanTrigger,
    ScanSeverity,
)

__all__ = [
    # Core classes
    "guard",
    "redact",
    "scan",
    # Guard types
    "GuardResult",
    "RoleContract",
    # Redact types
    "RedactResult",
    "EntityType",
    "FINANCE_ENTITIES",
    "STANDARD_ENTITIES",
    # Scan types
    "ScanResult",
    "ScanFinding",
    "ScanType",
    "ScanTrigger",
    "ScanSeverity",
]
