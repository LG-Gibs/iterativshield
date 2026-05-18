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

import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

@dataclass
class GuardResult:
    """IterativGuard™ extended response schema.

    Upstream fields (inherited):
        safe              -- True if input passed all checks
        classification    -- coarse violation class
        violation_types   -- list of specific violation identifiers

    IterativAI governance extensions:
        agent_id          -- UUID of the calling agent
        task_run_id       -- UUID of the active task run
        role_contract_id  -- UUID of the active role contract
        role_contract_version -- version of the role contract
        environment       -- deployment environment (dev | staging | prod)
        autonomy_level    -- A0–A5 (guard behavior tightens at lower levels)
        incident_created  -- True if an agent_incident record was created
        incident_id       -- UUID of the created incident, or None
        kill_switch_triggered -- True if incident severity triggered kill switch
    """
    # Upstream fields
    safe: bool
    classification: str
    violation_types: list[str]

    # IterativAI governance extensions
    agent_id: uuid.UUID | None = None
    task_run_id: uuid.UUID | None = None
    role_contract_id: uuid.UUID | None = None
    role_contract_version: int | None = None
    environment: str = "prod"
    autonomy_level: str = "A3"
    incident_created: bool = False
    incident_id: uuid.UUID | None = None
    kill_switch_triggered: bool = False


# ---------------------------------------------------------------------------
# Role contract stub
# ---------------------------------------------------------------------------

@dataclass
class RoleContract:
    """Minimal role contract representation for Guard policy binding."""
    id: uuid.UUID
    version: int
    prohibited_tasks: list[str] = field(default_factory=list)
    permitted_tools: list[str] = field(default_factory=list)
    subject_scope: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# IterativGuard™
# ---------------------------------------------------------------------------

class IterativGuard:
    """
    IterativGuard™ — governance-native prompt-injection and policy guard.

    Usage:
        guard = IterativGuard(model="superagent-guard-4b", environment="prod")
        result = guard.check(
            input=agent_input,
            role_contract=active_contract,
            agent_id=agent_uuid,
            task_run_id=task_uuid,
        )
        if not result.safe:
            raise RuntimeError(f"Guard blocked: {result.violation_types}")
    """

    # Supported self-hosted model tiers
    MODELS = {
        "superagent-guard-0.6b": {"tier": "dev",     "latency_ms": 20},
        "superagent-guard-1.7b": {"tier": "prod",    "latency_ms": 50},
        "superagent-guard-4b":   {"tier": "finance",  "latency_ms": 100},
    }

    def __init__(self, model: str = "superagent-guard-1.7b", environment: str = "prod") -> None:
        if model not in self.MODELS:
            raise ValueError(f"Unknown model: {model}. Choose from {list(self.MODELS)}.")
        self.model = model
        self.environment = environment

    def check(
        self,
        input: str,
        role_contract: RoleContract | None = None,
        agent_id: uuid.UUID | None = None,
        task_run_id: uuid.UUID | None = None,
        check_prohibited_tasks: bool = True,
        check_tool_scope: bool = True,
        check_subject_scope: bool = True,
    ) -> GuardResult:
        """
        Run injection + policy check on agent input or output.

        Args:
            input                 -- text to evaluate
            role_contract         -- active role contract for policy binding
            agent_id              -- UUID of the calling agent
            task_run_id           -- UUID of the active task run
            check_prohibited_tasks -- enforce role_contract.prohibited_tasks
            check_tool_scope      -- enforce role_contract.permitted_tools
            check_subject_scope   -- enforce role_contract.subject_scope

        Returns:
            GuardResult with governance fields populated.

        Note:
            This stub returns a safe=True placeholder.
            Replace with upstream superagent guard() inference call.
        """
        # TODO: call upstream superagent guard model inference here
        result = GuardResult(
            safe=True,
            classification="none",
            violation_types=[],
            agent_id=agent_id,
            task_run_id=task_run_id,
            role_contract_id=role_contract.id if role_contract else None,
            role_contract_version=role_contract.version if role_contract else None,
            environment=self.environment,
        )

        # TODO: integrate incident routing and kill-switch evaluation
        # if not result.safe:
        #     result.incident_id = create_agent_incident(result)
        #     result.incident_created = True
        #     result.kill_switch_triggered = evaluate_kill_switch(result)

        return result
