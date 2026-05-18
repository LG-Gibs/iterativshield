"""
iterative.shield
================
IterativShield™ — IterativAI’s governed safety layer.

Fork of superagent-ai/superagent (MIT).
Extends Guard, Redact, and Scan with IterativAI role-contract enforcement,
POPIA-aware redaction, and governance-native incident routing.

Canonical import:
    from iterativ.shield import guard, redact, scan

All inference is self-hosted. No data leaves IterativAI infrastructure.
"""

from iterativ.shield.guard import IterativGuard as guard
from iterativ.shield.redact import IterativRedact as redact
from iterativ.shield.scan import IterativScan as scan

__all__ = ["guard", "redact", "scan"]
__version__ = "1.0.0"
__author__ = "Iterativ (Pty) Ltd"
__license__ = "MIT"
