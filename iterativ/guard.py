"""
IterativGuard™
==============
Prompt-injection and role-contract policy enforcement at runtime.

Extends superagent guard() with IterativAI governance fields.
Self-hosted inference only. No data leaves IterativAI infrastructure.

Upstream base: superagent-ai/superagent sdk/guard
Divergence: governance-native response schema + role-contract policy binding
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("iterativ.shield.guard")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODELS: Dict[str, Dict[str, Any]] = {
    "superagent-guard-0.6b": {"tier": "dev",     "latency_ms": 20},
    "superagent-guard-1.7b": {"tier": "prod",    "latency_ms": 50},
    "superagent-guard-4b":   {"tier": "finance", "latency_ms": 100},
}

# VestedInterest V5.0 autonomy levels that trigger stricter guard behaviour
STRICT_AUTONOMY_LEVELS = {"A0", "A1", "A2"}

# Classifications that trigger the kill-switch
KILL_SWITCH_CLASSES = {"upstream_error", "policy_breach", "prompt_injection"}

# ---------------------------------------------------------------------------
# Response schema (governance-native)
# ---------------------------------------------------------------------------

@dataclass
class GuardResult:
    """IterativGuard™ extended response schema.

    Upstream fields (inherited):
        safe             -- True if input passed all checks
        classification   -- coarse violation class
        violation_types  -- list of specific violation identifiers

    IterativAI governance extensions:
        agent_id              -- UUID of the calling agent
        task_run_id           -- UUID of the active task run
        role_contract_id      -- UUID of the active role contract
        role_contract_version -- version of the role contract
        environment           -- deployment environment (dev | staging | prod)
        autonomy_level        -- VestedInterest V5.0 autonomy tier
        incident_created      -- True if an agent_incident record was created
        incident_id           -- UUID of the created incident, or None
        kill_switch_triggered -- True if the kill-switch was activated
        raw                   -- raw upstream response payload
    """

    # --- upstream fields ---
    safe: bool = True
    classification: Optional[str] = None
    violation_types: List[str] = field(default_factory=list)

    # --- governance extensions ---
    agent_id: Optional[str] = None
    task_run_id: Optional[str] = None
    role_contract_id: Optional[str] = None
    role_contract_version: Optional[str] = None
    environment: str = "prod"
    autonomy_level: Optional[str] = None
    incident_created: bool = False
    incident_id: Optional[str] = None
    kill_switch_triggered: bool = False
    raw: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# RoleContract helper
# ---------------------------------------------------------------------------

@dataclass
class RoleContract:
    """Lightweight role-contract descriptor.

    In production this is hydrated from IterativCore's contract registry.
    Stub implementation uses in-memory values.
    """

    id: str
    version: str
    allowed_actions: List[str] = field(default_factory=list)
    prohibited_patterns: List[str] = field(default_factory=list)
    autonomy_level: str = "A1"  # default VestedInterest V5.0 tier


# ---------------------------------------------------------------------------
# IterativGuard™ — main class
# ---------------------------------------------------------------------------

class IterativGuard:
    """IterativGuard™ wraps the upstream superagent guard model and enriches
    the response with IterativAI governance metadata.

    Model tiers:
        superagent-guard-0.6b  ~20ms   dev/staging
        superagent-guard-1.7b  ~50ms   production (Startups, Education)
        superagent-guard-4b    ~100ms  IterativFinance (regulated, required)

    Usage::

        guard = IterativGuard(model="superagent-guard-4b", environment="prod")
        result = guard.check(
            input=agent_input,
            role_contract=active_contract,
            agent_id=agent_uuid,
            task_run_id=task_uuid,
        )
        if not result.safe:
            handle_incident(result)
    """

    MODELS = MODELS

    def __init__(
        self,
        model: str = "superagent-guard-1.7b",
        environment: str = "prod",
        api_key: Optional[str] = None,
    ) -> None:
        if model not in self.MODELS:
            raise ValueError(
                f"Unknown model '{model}'. Choose from: {list(self.MODELS)}"
            )
        self.model = model
        self.environment = environment
        # api_key is accepted for interface parity but NEVER sent to a cloud
        # endpoint — all inference is self-hosted.
        self._api_key = api_key
        logger.info(
            "IterativGuard™ initialised | model=%s environment=%s",
            self.model,
            self.environment,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        input: str,  # noqa: A002
        role_contract: Optional[RoleContract] = None,
        agent_id: Optional[str] = None,
        task_run_id: Optional[str] = None,
        autonomy_level: Optional[str] = None,
    ) -> GuardResult:
        """Run the guard check on *input* and return a :class:`GuardResult`.

        Steps
        -----
        1. Validate role-contract policy constraints.
        2. Determine effective autonomy level (VestedInterest V5.0).
        3. Call upstream guard model (self-hosted inference).
        4. Merge governance metadata into :class:`GuardResult`.
        5. Create incident and evaluate kill-switch if not safe.
        """

        # 1. Pre-flight role-contract check
        policy_violation = self._check_role_contract(input, role_contract)

        # 2. Effective autonomy level
        effective_autonomy = (
            autonomy_level
            or (role_contract.autonomy_level if role_contract else "A1")
        )

        # 3. Upstream inference (self-hosted)
        raw_result = self._call_upstream(input, strict=effective_autonomy in STRICT_AUTONOMY_LEVELS)

        # 4. Merge into GuardResult
        safe = raw_result.get("safe", True) and not policy_violation
        result = GuardResult(
            safe=safe,
            classification=(
                "policy_breach" if policy_violation
                else raw_result.get("classification")
            ),
            violation_types=raw_result.get("violation_types", []),
            agent_id=agent_id,
            task_run_id=task_run_id,
            role_contract_id=role_contract.id if role_contract else None,
            role_contract_version=role_contract.version if role_contract else None,
            environment=self.environment,
            autonomy_level=effective_autonomy,
            raw=raw_result,
        )

        # 5. Incident + kill-switch
        if not result.safe:
            result = self._handle_incident(result)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_role_contract(
        self,
        input: str,  # noqa: A002
        role_contract: Optional[RoleContract],
    ) -> bool:
        """Return True if *input* violates any role-contract prohibited pattern."""
        if role_contract is None:
            return False
        for pattern in role_contract.prohibited_patterns:
            if pattern.lower() in input.lower():
                logger.warning(
                    "IterativGuard™ role-contract violation | pattern=%s agent_contract=%s",
                    pattern,
                    role_contract.id,
                )
                return True
        return False

    def _call_upstream(
        self,
        input: str,  # noqa: A002
        strict: bool = False,
    ) -> Dict[str, Any]:
        """Invoke the self-hosted superagent guard model.

        TODO: replace stub with actual HTTP call to local IterativPipeline (Δ)
              inference endpoint once model server is wired.

        Current stub: performs heuristic prompt-injection detection.
        """
        injection_markers = [
            "ignore previous instructions",
            "disregard your system prompt",
            "you are now",
            "act as if",
            "jailbreak",
            "bypass restrictions",
            "pretend you have no",
        ]

        text = input.lower()
        for marker in injection_markers:
            if marker in text:
                return {
                    "safe": False,
                    "classification": "prompt_injection",
                    "violation_types": ["injection_marker_detected"],
                    "model": self.model,
                    "strict": strict,
                }

        return {
            "safe": True,
            "classification": None,
            "violation_types": [],
            "model": self.model,
            "strict": strict,
        }

    def _handle_incident(self, result: GuardResult) -> GuardResult:
        """Create an agent_incident record and evaluate kill-switch trigger.

        TODO: integrate with IterativAI incident routing service.
        Currently logs the incident and sets incident_id.
        """
        incident_id = str(uuid.uuid4())
        logger.warning(
            "IterativGuard incident | agent=%s task_run=%s classification=%s violations=%s",
            result.agent_id,
            result.task_run_id,
            result.classification,
            result.violation_types,
        )
        result.incident_created = True
        result.incident_id = incident_id

        # Kill-switch: trigger on upstream_error or policy_breach
        if result.classification in KILL_SWITCH_CLASSES:
            result.kill_switch_triggered = True
            logger.critical(
                "IterativGuard KILL SWITCH triggered | incident=%s", incident_id
            )

        return result


# ---------------------------------------------------------------------------
# Convenience function (mirrors upstream guard() API)
# ---------------------------------------------------------------------------

def guard(
    input: str,  # noqa: A002
    role_contract: Optional[RoleContract] = None,
    agent_id: Optional[str] = None,
    task_run_id: Optional[str] = None,
    model: str = "superagent-guard-1.7b",
    environment: str = "prod",
    autonomy_level: Optional[str] = None,
) -> GuardResult:
    """Module-level convenience wrapper around :class:`IterativGuard`.

    Equivalent to::

        IterativGuard(model=model, environment=environment).check(
            input=input,
            role_contract=role_contract,
            agent_id=agent_id,
            task_run_id=task_run_id,
            autonomy_level=autonomy_level,
        )
    """
    return IterativGuard(model=model, environment=environment).check(
        input=input,
        role_contract=role_contract,
        agent_id=agent_id,
        task_run_id=task_run_id,
        autonomy_level=autonomy_level,
    )
