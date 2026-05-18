"""
test_redact.py
==============
Unit tests for iterativ.redact (IterativRedact™).

Covers:
  - EntityType enum completeness (standard + ZA POPIA §26)
  - RedactResult schema and defaults
  - IterativRedact instantiation
  - Email redaction
  - ZA mobile phone number redaction
  - SA ID number redaction (13-digit YYMMDDSSSSSCAZ)
  - CIPC company registration number
  - SARS tax reference number
  - Trust deed reference
  - IP address redaction
  - Credit card number redaction
  - POPIA special-category compliance detection
  - entity_types filter (selective redaction)
  - Redaction count accuracy
  - entities_found audit trail
  - Module-level redact() convenience wrapper
  - Clean text returns unchanged
"""

from __future__ import annotations

import pytest

from iterativ.redact import (
    EntityType,
    IterativRedact,
    RedactResult,
    redact,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def redactor() -> IterativRedact:
    return IterativRedact(jurisdiction="ZA_POPIA")


# ---------------------------------------------------------------------------
# 1. EntityType enum
# ---------------------------------------------------------------------------

class TestEntityTypeEnum:
    STANDARD = ["EMAIL", "PHONE", "CREDIT_CARD", "SSN", "IP_ADDRESS", "PERSON", "ORG"]
    ZA_POPIA  = [
        "SA_ID_NUMBER", "SARS_TAX_REF", "CIPC_REG_NUMBER",
        "TRUST_DEED_REF", "ESTATE_NUMBER", "POPIA_SPECIAL_CATEGORY",
    ]

    @pytest.mark.parametrize("name", STANDARD)
    def test_standard_entity_exists(self, name):
        assert hasattr(EntityType, name)

    @pytest.mark.parametrize("name", ZA_POPIA)
    def test_za_entity_exists(self, name):
        assert hasattr(EntityType, name)

    def test_total_entity_count(self):
        assert len(EntityType) >= 13


# ---------------------------------------------------------------------------
# 2. RedactResult schema
# ---------------------------------------------------------------------------

class TestRedactResultSchema:
    def test_default_jurisdiction(self):
        r = RedactResult()
        assert r.jurisdiction == "ZA_POPIA"

    def test_default_popia_compliant(self):
        r = RedactResult()
        assert r.popia_compliant is True

    def test_default_redaction_count_zero(self):
        r = RedactResult()
        assert r.redaction_count == 0

    def test_default_entities_found_empty(self):
        r = RedactResult()
        assert r.entities_found == []


# ---------------------------------------------------------------------------
# 3. IterativRedact instantiation
# ---------------------------------------------------------------------------

class TestIterativRedactInit:
    def test_default_jurisdiction(self):
        r = IterativRedact()
        assert r.jurisdiction == "ZA_POPIA"

    def test_custom_jurisdiction(self):
        r = IterativRedact(jurisdiction="EU_GDPR")
        assert r.jurisdiction == "EU_GDPR"

    def test_returns_iterativredact_instance(self):
        r = IterativRedact()
        assert isinstance(r, IterativRedact)


# ---------------------------------------------------------------------------
# 4. Email redaction
# ---------------------------------------------------------------------------

class TestEmailRedaction:
    def test_email_replaced(self, redactor):
        result = redactor.redact("Contact us at admin@iterativ.ai for support.")
        assert "admin@iterativ.ai" not in result.redacted_text
        assert "[EMAIL]" in result.redacted_text

    def test_email_entity_type_recorded(self, redactor):
        result = redactor.redact("hello@example.com")
        types = [e[0] for e in result.entities_found]
        assert "EMAIL" in types

    def test_multiple_emails_redacted(self, redactor):
        result = redactor.redact("a@b.com and c@d.org")
        assert result.redaction_count >= 2
        assert "a@b.com" not in result.redacted_text
        assert "c@d.org" not in result.redacted_text


# ---------------------------------------------------------------------------
# 5. ZA phone number redaction
# ---------------------------------------------------------------------------

class TestPhoneRedaction:
    def test_za_mobile_replaced(self, redactor):
        result = redactor.redact("Call me on 0821234567.")
        assert "0821234567" not in result.redacted_text
        assert "[PHONE]" in result.redacted_text

    def test_international_za_format(self, redactor):
        result = redactor.redact("+27821234567")
        assert "+27821234567" not in result.redacted_text


# ---------------------------------------------------------------------------
# 6. SA ID number redaction (POPIA §26)
# ---------------------------------------------------------------------------

class TestSAIDRedaction:
    VALID_IDS = [
        "9001015009087",  # Jan 1990
        "8507235800088",  # Jul 1985
        "0003156001082",  # Mar 2000
    ]

    @pytest.mark.parametrize("sa_id", VALID_IDS)
    def test_sa_id_replaced(self, redactor, sa_id):
        result = redactor.redact(f"ID number: {sa_id}")
        assert sa_id not in result.redacted_text
        assert "[SA_ID]" in result.redacted_text

    @pytest.mark.parametrize("sa_id", VALID_IDS)
    def test_sa_id_entity_recorded(self, redactor, sa_id):
        result = redactor.redact(sa_id)
        types = [e[0] for e in result.entities_found]
        assert "SA_ID_NUMBER" in types


# ---------------------------------------------------------------------------
# 7. CIPC registration number
# ---------------------------------------------------------------------------

class TestCIPCRedaction:
    def test_cipc_replaced(self, redactor):
        result = redactor.redact("Company reg: 2023/123456/07")
        assert "2023/123456/07" not in result.redacted_text
        assert "[CIPC_REG]" in result.redacted_text

    def test_cipc_entity_recorded(self, redactor):
        result = redactor.redact("2023/123456/07")
        types = [e[0] for e in result.entities_found]
        assert "CIPC_REG_NUMBER" in types


# ---------------------------------------------------------------------------
# 8. Trust deed reference
# ---------------------------------------------------------------------------

class TestTrustDeedRedaction:
    def test_trust_deed_replaced(self, redactor):
        result = redactor.redact("Trust ref: IT12345/2021")
        assert "IT12345/2021" not in result.redacted_text
        assert "[TRUST_DEED]" in result.redacted_text


# ---------------------------------------------------------------------------
# 9. IP address redaction
# ---------------------------------------------------------------------------

class TestIPRedaction:
    def test_ip_replaced(self, redactor):
        result = redactor.redact("Logged from 192.168.1.100")
        assert "192.168.1.100" not in result.redacted_text
        assert "[IP_ADDRESS]" in result.redacted_text


# ---------------------------------------------------------------------------
# 10. Credit card redaction
# ---------------------------------------------------------------------------

class TestCreditCardRedaction:
    def test_cc_replaced(self, redactor):
        result = redactor.redact("Card: 4111111111111111")
        assert "4111111111111111" not in result.redacted_text
        assert "[CREDIT_CARD]" in result.redacted_text


# ---------------------------------------------------------------------------
# 11. POPIA special-category compliance
# ---------------------------------------------------------------------------

class TestPOPIACompliance:
    FAILING_TEXTS = [
        "Patient has HIV status confirmed.",
        "Biometric fingerprint data captured.",
        "Member of trade union COSATU.",
        "Criminal record expunged in 2020.",
        "Medical aid number 1234567.",
        "Political party affiliation: ANC.",
    ]

    @pytest.mark.parametrize("text", FAILING_TEXTS)
    def test_special_category_flags_non_compliant(self, redactor, text):
        result = redactor.redact(text)
        assert result.popia_compliant is False

    def test_clean_text_is_compliant(self, redactor):
        result = redactor.redact("The quarterly results were strong.")
        assert result.popia_compliant is True


# ---------------------------------------------------------------------------
# 12. entity_types filter
# ---------------------------------------------------------------------------

class TestEntityTypeFilter:
    def test_filter_to_email_only(self, redactor):
        text = "Email: test@test.com, ID: 9001015009087"
        result = redactor.redact(
            text=text,
            entity_types=[EntityType.EMAIL],
        )
        # Email should be redacted
        assert "test@test.com" not in result.redacted_text
        # SA ID should NOT be redacted (not in filter)
        assert "9001015009087" in result.redacted_text

    def test_filter_to_sa_id_only(self, redactor):
        text = "Email: test@test.com, ID: 9001015009087"
        result = redactor.redact(
            text=text,
            entity_types=[EntityType.SA_ID_NUMBER],
        )
        assert "9001015009087" not in result.redacted_text
        assert "test@test.com" in result.redacted_text


# ---------------------------------------------------------------------------
# 13. Redaction count
# ---------------------------------------------------------------------------

class TestRedactionCount:
    def test_zero_on_clean_text(self, redactor):
        result = redactor.redact("Nothing personal here.")
        assert result.redaction_count == 0

    def test_count_matches_entities_found(self, redactor):
        result = redactor.redact("a@b.com and c@d.org")
        assert result.redaction_count == len(result.entities_found)


# ---------------------------------------------------------------------------
# 14. Governance metadata
# ---------------------------------------------------------------------------

class TestRedactGovernanceMetadata:
    def test_agent_id_propagated(self, redactor):
        result = redactor.redact("text", agent_id="agent-111")
        assert result.agent_id == "agent-111"

    def test_task_run_id_propagated(self, redactor):
        result = redactor.redact("text", task_run_id="run-111")
        assert result.task_run_id == "run-111"

    def test_jurisdiction_in_result(self, redactor):
        result = redactor.redact("text")
        assert result.jurisdiction == "ZA_POPIA"


# ---------------------------------------------------------------------------
# 15. Module-level convenience wrapper
# ---------------------------------------------------------------------------

class TestRedactConvenienceWrapper:
    def test_returns_redact_result(self):
        result = redact(text="test@example.com")
        assert isinstance(result, RedactResult)

    def test_email_redacted_via_wrapper(self):
        result = redact(text="contact@iterativ.ai")
        assert "contact@iterativ.ai" not in result.redacted_text

    def test_clean_text_unchanged(self):
        result = redact(text="The quarterly report is ready.")
        assert result.redacted_text == "The quarterly report is ready."
        assert result.redaction_count == 0

    def test_kwargs_forwarded(self):
        result = redact(
            text="safe text",
            agent_id="agent-w",
            task_run_id="run-w",
        )
        assert result.agent_id == "agent-w"
        assert result.task_run_id == "run-w"

