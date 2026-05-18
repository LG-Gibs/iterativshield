# IterativShield™

**IterativAI™ — Governed Safety Layer**
**Version:** 1.0
**Status:** Active customisation fork of `superagent-ai/superagent` (MIT)
**Canonical SDK namespace:** `from iterativ.shield import guard, redact, scan`

---

## What IterativShield™ Is

IterativShield™ is the platform safety layer for the IterativAI™ agentic runtime.
It is a governance-native fork of the Superagent SDK, extended to enforce:

- **IterativGuard™** — prompt-injection and role-contract policy enforcement at runtime
- **IterativRedact™** — PII/PHI/secrets redaction with POPIA §26 jurisdiction extensions
- **IterativScan™** — repository and tool poisoning detection; adversarial test runner

All inference runs self-hosted. No data leaves IterativAI infrastructure.

---

## Three Modules

### IterativGuard™
Extends `superagent guard()` with:
- Role-contract policy binding — rejects inputs that attempt prohibited tasks or out-of-scope tool calls
- Governance-native response schema: `agent_id`, `task_run_id`, `role_contract_id`, `autonomy_level`, `incident_created`, `kill_switch_triggered`
- Automatic `agent_incident` record creation on every `safe: false` result
- Kill-switch evaluation on high-severity incidents
- Review Queue routing for operator visibility

### IterativRedact™
Extends `superagent redact()` with South Africa jurisdiction entity types:
- `SA_ID_NUMBER` — 13-digit RSA Identity Number
- `SARS_TAX_REF` — SARS tax reference number
- `CIPC_REG_NUMBER` — Company registration number
- `TRUST_DEED_REF` — Trust deed reference
- `ESTATE_NUMBER` — Deceased estate reference
- `BANKING_DETAIL_ZA` — SA bank account and branch codes
- `POPIA_SPECIAL_CATEGORY` — Health, biometric, religious data (POPIA §26)

Mandatory checkpoints: input gate (before agent sees data) and output gate (before Review Queue).

### IterativScan™
Extends `superagent scan()` with:
- Pre-onboarding repo scans for all new agent integrations
- Periodic scans (weekly scheduled + triggered on dependency update)
- Adversarial test runner — wired to Agent Test Lab regression harness (pending upstream `test()` release)

---

## Self-Hosted Model Tiers

| Model | Parameters | Latency | Deployment |
|---|---|---|---|
| `superagent-guard-0.6b` | 0.6B | ~20ms | Dev/staging |
| `superagent-guard-1.7b` | 1.7B | ~50ms | Production (Startups, Education) |
| `superagent-guard-4b` | 4B | ~100ms | IterativFinance (regulated domains) |

All models sourced from HuggingFace. IterativFinance agents are hard-assigned to the 4B model.

---

## Runtime Flow

```
Agent Task Run
  → Input arrives at Tool Proxy
  → IterativGuard™.check(input, role_contract)  ← policy + injection check
        BLOCK → agent_incident → kill_switch eval → Review Queue
        ALLOW → continue
  → IterativRedact™.redact(input)               ← PII/PHI/secrets stripped
  → Agent processes clean input
  → Agent produces output
  → IterativGuard™.check(output, role_contract) ← output safety check
        BLOCK → agent_incident
        ALLOW → route to Review Queue
  → IterativScan™.scan()                        ← periodic repo/tool check
```

---

## What IterativShield™ Does Not Do

- It does not implement Review Queue logic — that is governed by IterativPipeline (Δ)
- It does not make business rule decisions — it enforces safety boundaries only
- It does not perform end-user content moderation
- It does not operate in managed-cloud mode — self-hosted inference only
- It cannot bypass INV-1: agents still cannot write directly to SKS

---

## Fork Maintenance Policy

1. **Security patches** from upstream applied within 14 days of release
2. **Model weights** evaluated on each upstream release; upgrade requires regression pass
3. **API stability** — `guard()`, `redact()`, `scan()` signatures are stable; internal extensions are additive only
4. **Feature incorporation** — upstream features incorporated selectively; no automatic merge
5. **POPIA entity types** reviewed annually against POPIA amendments

---

## Related Documents

- `UPSTREAM.md` — upstream tracking and merge policy
- `iterativ/guard.py` — IterativGuard™ module
- `iterativ/redact.py` — IterativRedact™ module
- `iterativ/scan.py` — IterativScan™ module
- Agent Workforce Layer™ Concept Document v1.1 — security model section
- IterativAI Agentic Runtime Orchestration Spec v1.0 — Tool Proxy and INV-1

---

*IterativShield™ is a registered trademark of Iterativ (Pty) Ltd, Cape Town, ZA.*
*Upstream: superagent-ai/superagent (MIT License). Fork maintained under MIT.*
