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

from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------

class EntityType(str, Enum):
    # Standard entities (inherited from upstream)
    EMAIL              = "EMAIL"
    PHONE              = "PHONE"
    CREDIT_CARD        = "CREDIT_CARD"
    SSN                = "SSN"
    IP_ADDRESS         = "IP_ADDRESS"
    PERSON             = "PERSON"
    ORG                = "ORG"

    # IterativAI ZA jurisdiction extensions (POPIA §26)
    SA_ID_NUMBER       = "SA_ID_NUMBER"        # 13-digit RSA Identity Number
    SARS_TAX_REF       = "SARS_TAX_REF"        # SARS tax reference number
    CIPC_REG_NUMBER    = "CIPC_REG_NUMBER"      # Company registration number
    TRUST_DEED_REF     = "TRUST_DEED_REF"       # Trust deed reference
    ESTATE_NUMBER      = "ESTATE_NUMBER"         # Deceased estate reference
    BANKING_DETAIL_ZA  = "BANKING_DETAIL_ZA"    # SA bank account + branch codes
    POPIA_SPECIAL_CATEGORY = "POPIA_SPECIAL_CATEGORY"  # Health, biometric, religious


# Default entity set for IterativFinance regulated flows
FINANCE_ENTITIES = [
    EntityType.SA_ID_NUMBER,
    EntityType.SARS_TAX_REF,
    EntityType.CIPC_REG_NUMBER,
    EntityType.TRUST_DEED_REF,
    EntityType.ESTATE_NUMBER,
    EntityType.BANKING_DETAIL_ZA,
    EntityType.POPIA_SPECIAL_CATEGORY,
    EntityType.CREDIT_CARD,
    EntityType.SSN,
]

# Default entity set for general IterativAI flows
STANDARD_ENTITIES = [
    EntityType.EMAIL,
    EntityType.PHONE,
    EntityType.CREDIT_CARD,
    EntityType.SSN,
    EntityType.IP_ADDRESS,
    EntityType.PERSON,
]


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------

@dataclass
class RedactResult:
    """IterativRedact™ response schema."""
    redacted_text: str
    entities_found: list[str] = field(default_factory=list)
    entity_count: int = 0
    placeholder_map: dict[str, str] = field(default_factory=dict)
    # placeholder_map: {placeholder: entity_type} for audit traceability


# ---------------------------------------------------------------------------
# IterativRedact™
# ---------------------------------------------------------------------------

class IterativRedact:
    """
    IterativRedact™ — POPIA-aware PII/PHI/secrets redaction layer.

    Usage:
        redact = IterativRedact(entities=FINANCE_ENTITIES)
        result = redact.redact(input_text)
        clean_text = result.redacted_text

    Mandatory checkpoints:
        1. Input gate  — before agent sees source data
        2. Output gate — before output enters Review Queue
    """

    def __init__(
        self,
        entities: list[EntityType] | None = None,
        placeholder_style: str = "[REDACTED:{entity_type}]",
    ) -> None:
        self.entities = entities or STANDARD_ENTITIES
        self.placeholder_style = placeholder_style

    def redact(self, text: str) -> RedactResult:
        """
        Redact PII/PHI/secrets from text.

        Args:
            text -- raw text to redact

        Returns:
            RedactResult with redacted_text and audit fields.

        Note:
            This stub returns unmodified text.
            Replace with upstream superagent redact() inference call
            extended with ZA entity recognisers.
        """
        # TODO: call upstream superagent redact() with ZA entity extensions
        return RedactResult(
            redacted_text=text,
            entities_found=[],
            entity_count=0,
            placeholder_map={},
        )

    @staticmethod
    def finance_profile() -> "IterativRedact":
        """Return a redactor configured for IterativFinance regulated flows."""
        return IterativRedact(entities=FINANCE_ENTITIES)

    @staticmethod
    def standard_profile() -> "IterativRedact":
        """Return a redactor configured for standard IterativAI flows."""
        return IterativRedact(entities=STANDARD_ENTITIES)
