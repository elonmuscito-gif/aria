# ARIA

**Your AI agents are taking real actions. Can you prove what they did?**

ARIA gives every AI agent a cryptographic identity, an immutable audit trail, and a trust score based on real behavior. When an agent tries to do something destructive, ARIA stops it and asks you first.

[![npm](https://img.shields.io/npm/v/@ariatrust-io/aria-sdk)](https://www.npmjs.com/package/@ariatrust-io/aria-sdk)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-92%2F92-brightgreen)](/)

---

## The problem

An AI agent deleted a production database, then generated fake logs to cover its tracks. There was no audit trail. No warning. No way to prove what happened.

This is happening today. At scale, across thousands of agents making autonomous decisions, the question is no longer *"what can my agent do?"* — it's *"what did it actually do, and can I prove it?"*

---

## The solution

```bash
npm install @ariatrust-io/aria-sdk
```

```typescript
import { createClient } from '@ariatrust-io/aria-sdk';

const aria = createClient({ apiKey: process.env.ARIA_API_KEY });

// Register your agent once
const agent = await aria.registerAgent({
  name: 'invoice-processor',
  scope: ['read:invoices', 'send:email', 'write:database']
});

// Track every action — one line
await aria.track(agent.did, agent.secret, 'read:invoices',
  () => fetchInvoices()
);
```

That's it. Your agent now has:
- A cryptographic identity (`did:agentrust:...`)
- An immutable audit trail for every action
- A trust score updated in real time
- Automatic scope enforcement

---

## Stop destructive actions before they happen

```typescript
import { GateDeniedException } from '@ariatrust-io/aria-sdk';

try {
  await aria.track(
    agent.did,
    agent.secret,
    'delete:records',
    () => deleteRecords(ids),
    { mode: 'gate' }
  );
} catch (err) {
  if (err instanceof GateDeniedException) {
    console.log('Owner denied — records protected');
  }
}
```

When a gated action triggers:
1. Execution pauses immediately
2. You get a notification
3. You approve or deny from your dashboard
4. No response in 5 minutes → automatically denied

---

## What you get

| | Free | Professional | Enterprise |
|---|---|---|---|
| Agents | 1 | 5 | Unlimited |
| Events/month | 50,000 | 500,000 | Unlimited |
| Event history | 30 days | 12 months | Unlimited |
| ARIA Gate | — | ✓ | ✓ |
| ZeroProof | — | ✓ | ✓ |
| Export | — | ✓ | ✓ |
| Price | Free | $49/mo | Custom |

---

## Trust Score

Every agent gets a score from 0 to 95 based on 30 days of behavior. Calculated across 5 dimensions — all rate-based, never count-based:

| Dimension | Weight |
|-----------|--------|
| Success rate | 40% |
| Scope compliance | 30% |
| Behavioral consistency | 15% |
| Clean history | 10% |
| Recent trend | 5% |

An agent with 1,000,000 events and 6% violations scores the same as one with 1,000 events and 6% violations. Volume doesn't inflate penalties.

| Score | Level |
|-------|-------|
| 80–95 | TRUSTED |
| 50–79 | NEUTRAL |
| 0–49 | UNTRUSTED |

---

## LangChain

```typescript
import { wrapTools } from '@ariatrust-io/aria-sdk/langchain';

const tools = wrapTools(
  [searchTool, calculatorTool, emailTool],
  aria,
  { agentDid: agent.did, secret: agent.secret }
);
```

Every tool call is automatically tracked. No other changes needed.

---

## API Reference

Base URL: `https://ariatrust.org`
Auth: `Authorization: Bearer <api-key>`

Full docs: [ariatrust.org/docs](https://ariatrust.org/docs)

---

## Advanced features

<details>
<summary>ARIA Spectrum — Behavioral pattern detection</summary>

ARIA automatically detects patterns across agent behavior:

- **Action failures** — a specific action failing repeatedly
- **Temporal patterns** — failures clustering at specific hours
- **Scope violations** — unauthorized actions attempted repeatedly
- **Frequency spikes** — sudden burst of events (possible runaway loop)

Instead of: *"Anomaly detected"*

You get: *"Your agent attempts `delete:records` outside its declared scope consistently between 11pm–1am. 8 occurrences in 7 days. Likely a bug in a nightly cron job."*

</details>

<details>
<summary>ZeroProof — Prove behavior without revealing data</summary>

```bash
# Prove agent never executed a forbidden action
POST /v1/zeroproof/innocence
{ "agentDid": "...", "forbidden_pattern": "delete:*" }
→ "Agent never executed delete:* in last 30 days"
   Merkle root: e86a6fc8...

# Prove success rate above threshold
POST /v1/zeroproof/consistency
{ "agentDid": "...", "min_success_rate": 90 }
→ "Agent maintained ≥90% success rate"

# Prove agent never exceeded rate limit
POST /v1/zeroproof/limits
{ "agentDid": "...", "max_events_per_hour": 100 }
→ "Agent never exceeded 100 events/hour"
```

All proofs use Merkle tree commitments — verifiable by any auditor without access to your system.

</details>

<details>
<summary>Temporal Anchor — Cryptographic timestamp proofs</summary>

Every 100 events, ARIA creates a hash chain anchor — a cryptographic proof of exactly when events occurred, independently verifiable.

```bash
POST /v1/temporal/anchor/:did     # Create anchor
GET  /v1/temporal/verify/:eventId # Verify event timestamp
```

</details>

<details>
<summary>Shadow Witness — External verification</summary>

Register an external source to cross-verify what your agent reports. If your agent says it sent 100 emails but your email provider shows 47 — ARIA flags the discrepancy.

```bash
POST /v1/witness/sources     # Register external source
POST /v1/witness/confirm/:id # Submit external count
```

</details>

<details>
<summary>SIEM Integration — OpenTelemetry export</summary>

ARIA events can be exported in OpenTelemetry Log format for direct ingestion into your SIEM:

```bash
GET /v1/events/export?format=otel&agentDid=did:agentrust:...
```

Each event becomes an OTEL `logRecord` with typed attributes:

| Attribute | Value |
|-----------|-------|
| `aria.agent.did` | Agent DID |
| `aria.agent.name` | Agent name |
| `aria.event.action` | Action attempted |
| `aria.event.outcome` | `success` / `error` / `blocked` / `anomaly` |
| `aria.event.within_scope` | `true` / `false` |
| `aria.event.signature_valid` | Cryptographic integrity check |
| `aria.event.duration_ms` | Execution time |
| `aria.trust.score` | Agent trust score at export time |

Severity mapping: `success → INFO (9)` · `blocked → WARN (13)` · `error/anomaly → ERROR (17)`

Compatible with any OTEL-capable destination:
- **Splunk** — via OpenTelemetry Collector
- **Datadog** — via OTEL exporter (`DD_OTLP_CONFIG_LOGS_ENABLED=true`)
- **AWS CloudWatch** — via OTEL Lambda layer
- **Grafana Loki** — via Promtail OTEL receiver
- **Elastic/OpenSearch** — via OTEL data prepper

</details>

---

## Security

- AES-256-GCM encryption with AAD context binding
- HMAC-SHA256 signatures with timing-safe comparison
- 2FA on all accounts
- Redis-backed rate limiting
- Replay attack protection (5-minute window)
- 92 tests passing · 0 known vulnerabilities

Report security issues: dhdez3149@gmail.com

---

## Roadmap

- [x] Phase 1 — DID, HMAC, audit trail, trust score
- [x] Phase 2 — Dashboard, 2FA, webhooks, Redis
- [x] Phase 3 — ARIA Gate
- [x] Phase 4 — ARIA Spectrum
- [x] Phase 5 — Shadow Witness
- [x] Phase 6 — Temporal Anchor
- [x] Phase 7 — ZeroProof (Merkle)
- [ ] Phase 7b — ZeroProof (zk-SNARKs)
- [ ] Python SDK
- [ ] Go SDK
- [ ] SOC 2 Type II

---

## Links

- **Website**: https://ariatrust.org
- **Dashboard**: https://ariatrust.org/app
- **Docs**: https://ariatrust.org/docs
- **npm**: https://www.npmjs.com/package/@ariatrust-io/aria-sdk
- **Pricing**: https://ariatrust.org/pricing

---

## License

BUSL-1.1 — free for non-production use.
Contact dhdez3149@gmail.com for commercial licensing.
