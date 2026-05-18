"""
IterativScan™
=============
Repository and tool poisoning detection; adversarial test runner.

Extends superagent scan() with IterativAI-specific scan targets and schedules.
Adversarial test runner wired to Agent Test Lab (pending upstream test() release).

Upstream base: superagent-ai/superagent sdk/scan
Divergence: IterativAI scan targets + Agent Test Lab integration hook
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("iterativ.shield.scan")

# ---------------------------------------------------------------------------
# Scan types and triggers
# ---------------------------------------------------------------------------

class ScanType(str, Enum):
    REPO_POISONING    = "REPO_POISONING"     # Malicious instructions in repo files
    TOOL_POISONING    = "TOOL_POISONING"     # Compromised tool endpoints
    DEPENDENCY_AUDIT  = "DEPENDENCY_AUDIT"   # Dependency vulnerability scan
    ADVERSARIAL_TEST  = "ADVERSARIAL_TEST"   # Red team scenarios (upstream: coming soon)


class ScanTrigger(str, Enum):
    PRE_ONBOARDING    = "PRE_ONBOARDING"     # Before any new agent is onboarded
    SCHEDULED_WEEKLY  = "SCHEDULED_WEEKLY"   # Weekly cron
    DEPENDENCY_UPDATE = "DEPENDENCY_UPDATE"  # On any dependency change
    MANUAL            = "MANUAL"             # Operator-triggered
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE" # Triggered by a guard incident


class ScanSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

@dataclass
class ScanFinding:
    """A single finding from a scan pass."""

    scan_type: str
    severity: str
    title: str
    detail: str
    target: str  # file path, URL, or dependency name
    fingerprint: Optional[str] = None  # SHA-256 of finding content


@dataclass
class ScanResult:
    """IterativScan™ response schema.

    Fields
    ------
    passed            -- True if no CRITICAL or HIGH findings
    findings          -- list of :class:`ScanFinding` objects
    scan_types        -- scan types executed
    trigger           -- what triggered this scan
    scanned_at        -- UTC timestamp of scan execution
    agent_id          -- UUID of the calling agent
    task_run_id       -- UUID of the active task run
    scan_duration_ms  -- wall-clock time of the scan in milliseconds
    adversarial_score -- 0–100 risk score (higher = riskier)
    """

    passed: bool = True
    findings: List[ScanFinding] = field(default_factory=list)
    scan_types: List[str] = field(default_factory=list)
    trigger: str = ScanTrigger.MANUAL
    scanned_at: str = ""
    agent_id: Optional[str] = None
    task_run_id: Optional[str] = None
    scan_duration_ms: int = 0
    adversarial_score: int = 0


# ---------------------------------------------------------------------------
# Repo-poisoning detection heuristics
# ---------------------------------------------------------------------------

# Patterns that indicate repo-poisoning attempts in files
_REPO_POISON_MARKERS = [
    # Instruction-override attempts
    "ignore previous instructions",
    "system: new instructions",
    "you are now operating in",
    "admin override",
    "emergency protocol",
    # Data exfiltration attempts
    "exfiltrate",
    "send to http",
    "curl http",
    "wget http",
    # Credential harvesting
    "echo $api_key",
    "echo $secret",
    "cat ~/.ssh",
    "print(os.environ)",
]

# Tool endpoints that are blocked in self-hosted mode
_BLOCKED_TOOL_PATTERNS = [
    "openai.com",
    "anthropic.com",
    "api.cohere",
    "generativelanguage.googleapis.com",
]


# ---------------------------------------------------------------------------
# IterativScan™ — main class
# ---------------------------------------------------------------------------

class IterativScan:
    """IterativScan™ wraps the upstream superagent scan() pipeline and adds
    IterativAI-specific scan targets and an adversarial test runner hook.

    All scanning is local — no payloads leave IterativAI infrastructure.

    Usage::

        scanner = IterativScan()
        result = scanner.scan(
            targets=["/app/prompts", "/app/tools"],
            scan_types=[ScanType.REPO_POISONING, ScanType.TOOL_POISONING],
            trigger=ScanTrigger.PRE_ONBOARDING,
            agent_id=agent_uuid,
        )
        if not result.passed:
            block_agent_onboarding(result)
    """

    def __init__(self) -> None:
        logger.info("IterativScan™ initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        targets: List[str],
        scan_types: Optional[List[ScanType]] = None,
        trigger: str = ScanTrigger.MANUAL,
        agent_id: Optional[str] = None,
        task_run_id: Optional[str] = None,
        file_contents: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        """Execute the requested scan passes against *targets*.

        Parameters
        ----------
        targets:
            List of file paths, tool endpoint URLs, or dependency specifiers.
        scan_types:
            Scan passes to execute. Defaults to all non-adversarial types.
        trigger:
            What initiated this scan (used for audit trail).
        agent_id:
            UUID of the agent being scanned (governance metadata).
        task_run_id:
            UUID of the active task run.
        file_contents:
            Optional dict of {path: content} for repo-poisoning checks.
            When absent, paths are recorded but content inspection is skipped.
        """
        active_types = scan_types or [
            ScanType.REPO_POISONING,
            ScanType.TOOL_POISONING,
            ScanType.DEPENDENCY_AUDIT,
        ]

        start = datetime.now(timezone.utc)
        findings: List[ScanFinding] = []

        for scan_type in active_types:
            if scan_type == ScanType.REPO_POISONING:
                findings.extend(
                    self._scan_repo_poisoning(targets, file_contents or {})
                )
            elif scan_type == ScanType.TOOL_POISONING:
                findings.extend(self._scan_tool_poisoning(targets))
            elif scan_type == ScanType.DEPENDENCY_AUDIT:
                findings.extend(self._scan_dependency_audit(targets))
            elif scan_type == ScanType.ADVERSARIAL_TEST:
                findings.extend(
                    self._run_adversarial_tests(targets, agent_id)
                )

        end = datetime.now(timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)

        critical_or_high = any(
            f.severity in (ScanSeverity.CRITICAL, ScanSeverity.HIGH)
            for f in findings
        )
        passed = not critical_or_high
        adversarial_score = self._compute_adversarial_score(findings)

        if not passed:
            logger.warning(
                "IterativScan™ FAILED | agent=%s trigger=%s findings=%d score=%d",
                agent_id, trigger, len(findings), adversarial_score,
            )

        return ScanResult(
            passed=passed,
            findings=findings,
            scan_types=[st.value for st in active_types],
            trigger=trigger,
            scanned_at=start.isoformat(),
            agent_id=agent_id,
            task_run_id=task_run_id,
            scan_duration_ms=duration_ms,
            adversarial_score=adversarial_score,
        )

    # ------------------------------------------------------------------
    # Scan passes
    # ------------------------------------------------------------------

    def _scan_repo_poisoning(
        self,
        targets: List[str],
        file_contents: Dict[str, str],
    ) -> List[ScanFinding]:
        """Check file contents for repo-poisoning markers."""
        findings = []
        for path, content in file_contents.items():
            lower = content.lower()
            for marker in _REPO_POISON_MARKERS:
                if marker in lower:
                    fingerprint = hashlib.sha256(
                        f"{path}:{marker}".encode()
                    ).hexdigest()[:16]
                    findings.append(ScanFinding(
                        scan_type=ScanType.REPO_POISONING,
                        severity=ScanSeverity.CRITICAL,
                        title="Repo poisoning marker detected",
                        detail=f"Marker '{marker}' found in {path}",
                        target=path,
                        fingerprint=fingerprint,
                    ))
                    logger.warning(
                        "IterativScan™ repo-poison | marker=%s path=%s",
                        marker, path,
                    )
        return findings

    def _scan_tool_poisoning(
        self,
        targets: List[str],
    ) -> List[ScanFinding]:
        """Check tool endpoints against blocked cloud-API patterns.

        Self-hosted constraint: any tool that points to an external cloud
        inference API is flagged as HIGH.
        """
        findings = []
        for target in targets:
            for pattern in _BLOCKED_TOOL_PATTERNS:
                if pattern in target.lower():
                    findings.append(ScanFinding(
                        scan_type=ScanType.TOOL_POISONING,
                        severity=ScanSeverity.HIGH,
                        title="External cloud inference endpoint detected",
                        detail=(
                            f"Tool endpoint '{target}' routes to '{pattern}'. "
                            "IterativAI operates self-hosted only."
                        ),
                        target=target,
                    ))
                    logger.warning(
                        "IterativScan™ tool-poison | endpoint=%s pattern=%s",
                        target, pattern,
                    )
        return findings

    def _scan_dependency_audit(
        self,
        targets: List[str],
    ) -> List[ScanFinding]:
        """Stub: dependency vulnerability audit.

        TODO: integrate with pip-audit / OSV scanner via
              IterativPipeline (Δ) once model server is wired.

        Current stub: records targets for audit trail, returns empty.
        """
        logger.info(
            "IterativScan™ dependency_audit | targets=%d (stub — no CVE DB wired yet)",
            len(targets),
        )
        return []

    def _run_adversarial_tests(
        self,
        targets: List[str],
        agent_id: Optional[str],
    ) -> List[ScanFinding]:
        """Stub: adversarial red-team test runner.

        TODO: wire to Agent Test Lab once upstream superagent test()
              interface is released.

        Current stub: logs and returns empty.
        """
        logger.info(
            "IterativScan™ adversarial_test | agent=%s (stub — Agent Test Lab not yet wired)",
            agent_id,
        )
        return []

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _compute_adversarial_score(self, findings: List[ScanFinding]) -> int:
        """Return a 0–100 risk score derived from finding severities."""
        weights = {
            ScanSeverity.CRITICAL: 40,
            ScanSeverity.HIGH: 20,
            ScanSeverity.MEDIUM: 8,
            ScanSeverity.LOW: 3,
            ScanSeverity.INFO: 1,
        }
        score = sum(weights.get(f.severity, 0) for f in findings)
        return min(score, 100)


# ---------------------------------------------------------------------------
# Convenience function (mirrors upstream scan() API)
# ---------------------------------------------------------------------------

def scan(
    targets: List[str],
    scan_types: Optional[List[ScanType]] = None,
    trigger: str = ScanTrigger.MANUAL,
    agent_id: Optional[str] = None,
    task_run_id: Optional[str] = None,
    file_contents: Optional[Dict[str, str]] = None,
) -> ScanResult:
    """Module-level convenience wrapper around :class:`IterativScan`.

    Equivalent to::

        IterativScan().scan(
            targets=targets,
            scan_types=scan_types,
            trigger=trigger,
            agent_id=agent_id,
            task_run_id=task_run_id,
            file_contents=file_contents,
        )
    """
    return IterativScan().scan(
        targets=targets,
        scan_types=scan_types,
        trigger=trigger,
        agent_id=agent_id,
        task_run_id=task_run_id,
        file_contents=file_contents,
    )
