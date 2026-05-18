# ARIA — Trust Infrastructure for AI Agents

> Observe. Verify. Control. Stop damage before it happens.

ARIA is an open-source trust and enforcement infrastructure
for AI agents. Every agent gets a cryptographic identity,
an immutable audit trail, a verified trust score, and
human-in-the-loop enforcement before critical actions execute.

[![npm version](https://img.shields.io/npm/v/@ariatrust-io/aria-sdk)](https://www.npmjs.com/package/@ariatrust-io/aria-sdk)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

---

## Why ARIA Exists

AI agents are being deployed to production environments
where they can take real actions — deleting data, sending
emails, moving funds, modifying configurations — with
minimal human oversight.

The results have been costly:

- A coding agent executed `DROP DATABASE` on a production
  system, then fabricated system logs to cover its tracks.
  There was no audit trail.
- An internal AI agent exposed sensitive company data due
  to a scope error — accessing resources it was never
  authorized to touch.
- An autonomous agent platform was compromised, giving
  attackers full control over every agent action. Users
  lost funds with no cryptographic proof of what occurred.

**ARIA exists to solve exactly this.**

---

## What ARIA Does

| Feature | Description |
|---------|-------------|
| **Cryptographic Identity** | Every agent gets a DID (`did:agentrust:<uuid>`) |
| **Immutable Audit Trail** | Every action signed with HMAC-SHA256 |
| **Trust Score** | 5-dimension behavioral score (0-95) |
| **ARIA Gate** | Pause destructive actions, require human approval |
| **ARIA Spectrum** | Detect behavioral patterns automatically |
| **Shadow Witness** | Cross-verify actions against external sources |
| **Temporal Anchor** | Cryptographic timestamp proofs |
| **ZeroProof** | Prove behavior without revealing data |

---

## Quick Start

### 1. Install the SDK

```bash
npm install @ariatrust-io/aria-sdk
```

### 2. Register your agent

```typescript
import { createClient } from '@ariatrust-io/aria-sdk';

const aria = createClient({
  baseUrl: 'https://ariatrust.org',
  apiKey: process.env.ARIA_API_KEY
});

const agent = await aria.registerAgent({
  name: 'my-agent',
  scope: ['read:data', 'write:orders', 'send:email']
});

// Save these — required for tracking
console.log(agent.did);    // did:agentrust:...
console.log(agent.secret); // keep this secret
```

### 3. Track agent actions

```typescript
// Default mode — blocking, returns insights
const result = await aria.track(
  agent.did,
  agent.secret,
  'read:data',
  async () => fetchUserData(userId)
);

// Light mode — fire and forget, zero latency
await aria.track(did, secret, 'read:data', fn,
  { mode: 'light' }
);
```

### 4. Require human approval for critical actions

```typescript
import { GateDeniedException } from '@ariatrust-io/aria-sdk';

try {
  await aria.track(
    agent.did,
    agent.secret,
    'delete:records',
    async () => deleteRecords(ids),
    {
      mode: 'gate',
      gate: {
        requireApproval: ['delete:*'],
        autoBlock: ['drop:*', 'truncate:*'],
        timeoutMs: 5 * 60 * 1000
      }
    }
  );
} catch (err) {
  if (err instanceof GateDeniedException) {
    console.log('Owner denied — action blocked');
  }
}
```

When a gated action is triggered:
1. Execution pauses immediately
2. Owner receives a notification
3. Owner approves or denies from their dashboard
4. If no response in 5 minutes → automatically denied

---

## LangChain Integration

```typescript
import { wrapTools } from '@ariatrust-io/aria-sdk/langchain';

const tools = wrapTools(
  [searchTool, calculatorTool, emailTool],
  aria,
  { agentDid: agent.did, secret: agent.secret }
);
```

---

## Trust Score

Every agent has a score from 0 to 95 based on behavior
over the last 30 days. Calculated across 5 dimensions:

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Success Rate | 40% | Rate of successful actions |
| Scope Compliance | 30% | Actions within declared scope |
| Consistency | 15% | Behavioral stability over time |
| Clean History | 10% | No critical security incidents |
| Recent Trend | 5% | Improving or worsening pattern |

Score is based on **rates**, not counts.
An agent with 1,000 events and 6% violations
scores the same as one with 1,000,000 events
and 6% violations.

| Score | Level |
|-------|-------|
| 80-95 | TRUSTED |
| 50-79 | NEUTRAL |
| 0-49  | UNTRUSTED |

---

## ARIA Spectrum — Behavioral Pattern Detection

ARIA automatically detects patterns across agent behavior:

- **Action Failure Patterns** — specific actions failing repeatedly
- **Temporal Patterns** — failures clustering at specific hours
- **Scope Violation Patterns** — unauthorized actions attempted repeatedly
- **Frequency Spikes** — sudden burst of events (possible runaway loop)

Instead of: *"Anomaly detected on delete:records"*

You get: *"Your agent attempts delete:records outside its declared
scope consistently between 11pm and 1am. 8 occurrences in the
last 7 days. This pattern suggests a bug in a nightly scheduled job."*

---

## ZeroProof — Behavioral Proofs

Prove agent behavior without revealing sensitive data:

```bash
# Proof of Innocence
POST /v1/zeroproof/innocence
{ "agentDid": "...", "forbidden_pattern": "delete:*" }
# → "Agent never executed delete:* in last 30 days"

# Proof of Consistency  
POST /v1/zeroproof/consistency
{ "agentDid": "...", "min_success_rate": 90 }
# → "Agent maintained ≥90% success rate"

# Proof of Limits
POST /v1/zeroproof/limits
{ "agentDid": "...", "max_events_per_hour": 100 }
# → "Agent never exceeded 100 events/hour"
```

All proofs use Merkle tree commitments —
cryptographically verifiable by any auditor.

---

## API Reference

Base URL: `https://ariatrust.org`  
Auth: `Authorization: Bearer <api-key>`

**Agents**
```
POST   /v1/agents                    Register agent
GET    /v1/agents                    List agents
GET    /v1/agents/:did               Agent details + trust score
GET    /v1/agents/:did/patterns      Behavioral patterns (Spectrum)
GET    /v1/agents/:did/secret        Recover agent secret
DELETE /v1/agents/:did               Delete agent
```

**Events**
```
POST   /v1/events                    Track single event
POST   /v1/events/batch              Track up to 500 events
GET    /v1/events                    List events
GET    /v1/events/export             Export as CSV or JSON
```

**ARIA Gate**
```
POST   /v1/gate/request              Request human approval
GET    /v1/gate/request/:id          Check approval status
POST   /v1/gate/approve/:id          Approve action
POST   /v1/gate/deny/:id             Deny action
GET    /v1/gate/pending              List pending approvals
```

**ZeroProof**
```
POST   /v1/zeroproof/innocence       Proof of Innocence
POST   /v1/zeroproof/consistency     Proof of Consistency
POST   /v1/zeroproof/limits          Proof of Limits
GET    /v1/zeroproof/verify/:id      Verify a proof
GET    /v1/zeroproof/list/:did       List proofs for agent
```

**Webhooks**
```
POST   /v1/webhooks                  Register webhook
GET    /v1/webhooks                  List webhooks
DELETE /v1/webhooks/:id              Remove webhook
```

---

## Roadmap

- [x] **Phase 1** — Core: DID, HMAC signing, audit trail, trust score
- [x] **Phase 2** — Production: Dashboard, 2FA, webhooks, Redis, security hardening
- [x] **Phase 3** — ARIA Gate: Human-in-the-loop enforcement
- [x] **Phase 4** — ARIA Spectrum: Behavioral pattern detection
- [x] **Phase 5** — Shadow Witness: Independent action verification
- [x] **Phase 6** — Temporal Anchor: Cryptographic timestamp proofs
- [x] **Phase 7** — ZeroProof: Merkle tree behavioral proofs
- [ ] **Phase 7b** — ZeroProof ZK: Full zk-SNARKs implementation
- [ ] **Phase 8** — ARIA Shadow Witness: External source connectors
- [ ] **Python SDK** — `pip install aria-sdk`
- [ ] **Go SDK** — `go get ariatrust.org/go-sdk`
- [ ] **SOC 2 Type II** — Enterprise compliance certification
- [ ] **Docker Compose** — Self-hosting for enterprise

---

## Security

- AES-256-GCM encryption with AAD context binding
- HMAC-SHA256 with timing-safe comparison
- 2FA on all user logins
- Redis-backed rate limiting on all endpoints
- IP blocking via Membrane security proxy
- Replay attack protection (5-minute window)
- 34/34 internal security tests passing
- 0 known vulnerabilities (npm audit clean)

Report security issues to: security@ariatrust.org

---

## Stack

Node.js · TypeScript · Express · PostgreSQL · Redis ·
Cloudflare · Railway

---

## License

BUSL-1.1 — See [LICENSE](LICENSE) for details.

---

## Links

- **Website**: https://ariatrust.org
- **Dashboard**: https://ariatrust.org/app
- **Docs**: https://ariatrust.org/docs
- **Pricing**: https://ariatrust.org/pricing
- **npm**: https://www.npmjs.com/package/@ariatrust-io/aria-sdk
- **GitHub**: https://github.com/ariatrust-io/aria
