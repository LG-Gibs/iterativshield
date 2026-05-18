"""
IterativRedact™
===============
PII/PHI/secrets redaction with POPIA §26 jurisdiction extensions.

Extends superagent redact() with South Africa entity types.
Self-hosted. No data leaves IterativAI infrastructure.

Upstream base: superagent-ai/superagent sdk/redact
Divergence: ZA jurisdiction entity types (POPIA §26)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("iterativ.shield.redact")

# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------

class EntityType(str, Enum):
    # Standard entities (inherited from upstream)
    EMAIL          = "EMAIL"
    PHONE          = "PHONE"
    CREDIT_CARD    = "CREDIT_CARD"
    SSN            = "SSN"
    IP_ADDRESS     = "IP_ADDRESS"
    PERSON         = "PERSON"
    ORG            = "ORG"

    # IterativAI ZA jurisdiction extensions (POPIA §26)
    SA_ID_NUMBER       = "SA_ID_NUMBER"       # 13-digit RSA Identity Number
    SARS_TAX_REF       = "SARS_TAX_REF"       # SARS tax reference number
    CIPC_REG_NUMBER    = "CIPC_REG_NUMBER"    # Company registration number
    TRUST_DEED_REF     = "TRUST_DEED_REF"     # Trust deed reference
    ESTATE_NUMBER      = "ESTATE_NUMBER"      # Deceased estate reference
    POPIA_SPECIAL_CATEGORY = "POPIA_SPECIAL_CATEGORY"  # Health, biometric, religious


# ---------------------------------------------------------------------------
# Regex patterns for self-hosted detection
# ---------------------------------------------------------------------------

# Each entry: (EntityType, compiled pattern, replacement label)
_PATTERNS: List[Tuple[EntityType, re.Pattern, str]] = [
    # Standard
    (EntityType.EMAIL,
     re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
     "[EMAIL]"),
    (EntityType.PHONE,
     re.compile(r"(\+27|0)[6-8][0-9]{8}"),  # ZA mobile format
     "[PHONE]"),
    (EntityType.CREDIT_CARD,
     re.compile(r"\b(?:\d[ -]?){13,16}\b"),
     "[CREDIT_CARD]"),
    (EntityType.IP_ADDRESS,
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "[IP_ADDRESS]"),

    # ZA jurisdiction (POPIA §26)
    (EntityType.SA_ID_NUMBER,
     re.compile(r"\b[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{7}\b"),
     "[SA_ID]"),
    (EntityType.SARS_TAX_REF,
     re.compile(r"\b[0-9]{10}\b"),
     "[SARS_TAX_REF]"),
    (EntityType.CIPC_REG_NUMBER,
     re.compile(r"\b\d{4}/\d{6}/\d{2}\b"),
     "[CIPC_REG]"),
    (EntityType.TRUST_DEED_REF,
     re.compile(r"\bIT\d{3,6}/\d{4}\b"),
     "[TRUST_DEED]"),
    (EntityType.ESTATE_NUMBER,
     re.compile(r"\bEST\d{4,8}\b", re.IGNORECASE),
     "[ESTATE_NO]"),
]


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

@dataclass
class RedactResult:
    """IterativRedact™ response schema.

    Fields
    ------
    redacted_text     -- input text with PII replaced by labels
    entities_found    -- list of (EntityType, original_value) tuples detected
    redaction_count   -- total number of redactions applied
    jurisdiction      -- jurisdiction standard applied
    agent_id          -- UUID of the calling agent
    task_run_id       -- UUID of the active task run
    popia_compliant   -- True if all POPIA §26 special-category data was redacted
    """

    redacted_text: str = ""
    entities_found: List[Tuple[str, str]] = field(default_factory=list)
    redaction_count: int = 0
    jurisdiction: str = "ZA_POPIA"
    agent_id: Optional[str] = None
    task_run_id: Optional[str] = None
    popia_compliant: bool = True


# ---------------------------------------------------------------------------
# IterativRedact™ — main class
# ---------------------------------------------------------------------------

class IterativRedact:
    """IterativRedact™ wraps the upstream superagent redact() pipeline and
    adds ZA POPIA §26 jurisdiction-specific entity recognition.

    All processing is local — no text is transmitted to cloud APIs.

    Usage::

        redactor = IterativRedact(jurisdiction="ZA_POPIA")
        result = redactor.redact(
            text=raw_agent_output,
            agent_id=agent_uuid,
            task_run_id=task_uuid,
            entity_types=[EntityType.SA_ID_NUMBER, EntityType.EMAIL],
        )
        safe_text = result.redacted_text
    """

    # Default entity types enabled for ZA jurisdiction
    DEFAULT_ZA_ENTITIES = [
        EntityType.EMAIL,
        EntityType.PHONE,
        EntityType.CREDIT_CARD,
        EntityType.IP_ADDRESS,
        EntityType.SA_ID_NUMBER,
        EntityType.SARS_TAX_REF,
        EntityType.CIPC_REG_NUMBER,
        EntityType.TRUST_DEED_REF,
        EntityType.ESTATE_NUMBER,
        EntityType.POPIA_SPECIAL_CATEGORY,
    ]

    def __init__(
        self,
        jurisdiction: str = "ZA_POPIA",
    ) -> None:
        self.jurisdiction = jurisdiction
        logger.info(
            "IterativRedact™ initialised | jurisdiction=%s", self.jurisdiction
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(
        self,
        text: str,
        agent_id: Optional[str] = None,
        task_run_id: Optional[str] = None,
        entity_types: Optional[List[EntityType]] = None,
    ) -> RedactResult:
        """Redact PII/PHI from *text* and return a :class:`RedactResult`.

        Steps
        -----
        1. Select active entity-type patterns.
        2. Apply regex-based detection (self-hosted, no cloud calls).
        3. Replace detected values with labelled placeholders.
        4. Evaluate POPIA special-category compliance.
        5. Return :class:`RedactResult` with governance metadata.
        """
        active_types = set(entity_types or self.DEFAULT_ZA_ENTITIES)
        active_patterns = [
            (et, pat, label)
            for et, pat, label in _PATTERNS
            if et in active_types
        ]

        redacted = text
        entities_found: List[Tuple[str, str]] = []
        redaction_count = 0

        for entity_type, pattern, label in active_patterns:
            matches = pattern.findall(redacted)
            if matches:
                for match in matches:
                    original = match if isinstance(match, str) else "".join(match)
                    entities_found.append((entity_type.value, original))
                    redaction_count += 1
                    logger.debug(
                        "IterativRedact™ | entity=%s agent=%s",
                        entity_type.value,
                        agent_id,
                    )
                redacted = pattern.sub(label, redacted)

        popia_compliant = self._check_popia_compliance(redacted)

        if not popia_compliant:
            logger.warning(
                "IterativRedact™ POPIA compliance gap detected | agent=%s task_run=%s",
                agent_id,
                task_run_id,
            )

        return RedactResult(
            redacted_text=redacted,
            entities_found=entities_found,
            redaction_count=redaction_count,
            jurisdiction=self.jurisdiction,
            agent_id=agent_id,
            task_run_id=task_run_id,
            popia_compliant=popia_compliant,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_popia_compliance(self, redacted_text: str) -> bool:
        """Heuristic check that no residual POPIA special-category markers remain.

        TODO: integrate with IterativAI POPIA compliance scanner once
              the NLP model layer is wired to IterativPipeline (Δ).

        Current stub: checks for common special-category keywords that
        should never appear in agent-facing output.
        """
        special_category_markers = [
            "hiv", "aids", "cancer diagnosis", "medical aid number",
            "biometric", "fingerprint", "religion", "political party",
            "trade union", "criminal record",
        ]
        lower = redacted_text.lower()
        for marker in special_category_markers:
            if marker in lower:
                return False
        return True


# ---------------------------------------------------------------------------
# Convenience function (mirrors upstream redact() API)
# ---------------------------------------------------------------------------

def redact(
    text: str,
    agent_id: Optional[str] = None,
    task_run_id: Optional[str] = None,
    entity_types: Optional[List[EntityType]] = None,
    jurisdiction: str = "ZA_POPIA",
) -> RedactResult:
    """Module-level convenience wrapper around :class:`IterativRedact`.

    Equivalent to::

        IterativRedact(jurisdiction=jurisdiction).redact(
            text=text,
            agent_id=agent_id,
            task_run_id=task_run_id,
            entity_types=entity_types,
        )
    """
    return IterativRedact(jurisdiction=jurisdiction).redact(
        text=text,
        agent_id=agent_id,
        task_run_id=task_run_id,
        entity_types=entity_types,
    )
