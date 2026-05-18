# UPSTREAM.md

**IterativShield™ — Upstream Tracking and Merge Policy**

---

## Upstream Repository

| Field | Value |
|---|---|
| Upstream | `superagent-ai/superagent` |
| Upstream URL | https://github.com/superagent-ai/superagent |
| License | MIT |
| Fork base commit | `5adc62d` (main, May 18 2026) |
| Fork branch | `iterativ/customise` |
| IterativAI SDK namespace | `iterativ.shield` |

---

## What We Track

We track the upstream `main` branch for:

1. **Security patches** — any commit tagged `security` or `fix: injection`, `fix: redact`, `fix: scan`
2. **Model weight releases** — new `superagent-guard-*` model versions on HuggingFace
3. **API surface changes** — any change to `guard()`, `redact()`, `scan()`, or `test()` signatures
4. **`test()` release** — the adversarial test runner, currently marked upstream as coming soon

## What We Do Not Auto-Merge

- Cloud API endpoint additions or changes (we run self-hosted only)
- Managed-API key flows
- Branding, marketing, or documentation changes
- Dependency upgrades unless they include a security patch
- Any upstream commit that modifies `guard()`, `redact()`, or `scan()` signatures without a regression pass

---

## Merge Policy

### Security Patches
- **SLA:** Applied within 14 days of upstream release
- **Process:** Cherry-pick to `iterativ/customise`; regression suite must pass before merge to `main`
- **Owner:** Platform engineering

### Model Weight Upgrades
- **Trigger:** New `superagent-guard-*` model published on HuggingFace
- **Process:** Evaluate accuracy/latency trade-off per tier; run IterativFinance regression suite; update model tier table in `ITERATIV_SHIELD.md`
- **Owner:** ML platform team

### API Surface Changes
- **Trigger:** Any upstream PR that touches `guard()`, `redact()`, `scan()`, or `test()`
- **Process:** Review diff; assess impact on IterativAI governance extensions; port compatible changes; reject incompatible changes and document in this file
- **Owner:** Platform engineering

### `test()` Release (Coming Soon)
- **Trigger:** Upstream ships `client.test()` red team capability
- **Process:** Evaluate; extend with IterativAI role contract constraints as the test policy; wire into Agent Test Lab regression harness
- **Owner:** Platform engineering + Agent Workforce Layer team

---

## Upstream Sync Cadence

| Activity | Frequency |
|---|---|
| Upstream diff review | Weekly (automated GitHub Action) |
| Security patch application | Within 14 days of upstream release |
| Model weight evaluation | On each upstream model release |
| Full upstream rebase assessment | Quarterly |

---

## Divergence Log

This table records deliberate divergences from upstream — places where IterativShield™ intentionally differs from `superagent-ai/superagent`.

| Date | Area | Upstream behaviour | IterativShield™ behaviour | Reason |
|---|---|---|---|---|
| 2026-05-18 | Cloud API | Supports managed cloud API mode | Removed — self-hosted only | Data sovereignty; IterativFinance compliance |
| 2026-05-18 | SDK namespace | `from superagent import ...` | `from iterativ.shield import guard, redact, scan` | IterativAI first-party branding |
| 2026-05-18 | Guard response schema | Returns `{safe, classification, violation_types}` | Extended with governance fields | Governance-native incident routing |
| 2026-05-18 | Redact entity types | Standard PII/PHI entities | + ZA jurisdiction entities (POPIA §26) | South Africa regulatory compliance |

---

## Adding a New Divergence

When a deliberate divergence is introduced:
1. Add a row to the Divergence Log above
2. Commit the row in the same PR as the divergence
3. Label the PR `iterativ-divergence`
4. Tag the platform engineering lead for review

---

*Maintained by Iterativ (Pty) Ltd, Cape Town, ZA.*
