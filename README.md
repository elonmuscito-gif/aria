# ARIA — Autonomous Registry for Intelligence Accountability

> Trust infrastructure for AI agents. Every agent gets a cryptographic identity, an immutable audit trail, and a verified reputation score.

## What is ARIA?

ARIA is the accountability layer the AI industry is missing. Companies deploy AI agents that act on their behalf — sending emails, processing payments, accessing databases. ARIA makes those agents auditable, verifiable, and trustworthy.


## Quick Start

```bash
npm install @ariatrust-io/aria-sdk
```

```typescript
import { createClient } from '@ariatrust-io/aria-sdk';

const aria = createClient({
  baseUrl: 'https://aria-production-0458.up.railway.app',
  apiKey: 'your-api-key'
});

// Register your agent
const agent = await aria.registerAgent({
  name: 'invoice-processor',
  scope: ['read:invoices', 'write:invoices']
});

// Track every action — get insights back
const result = await aria.track(
  agent.did,
  agent.secret,
  'read:invoices',
  async () => {
    // your agent logic here
  }
);

console.log(result.insights);
// {
//   scope: { valid: true, attempted: 'read:invoices' },
//   signature: { valid: true },
//   rateLimit: { exceeded: false, current: 1, limit: 100 },
//   trustScore: { impact: +1 }
// }
```

## Dashboard

Manage your agents visually at: https://aria-production-0458.up.railway.app/app

---

## API

Base URL: `https://aria-production-0458.up.railway.app`

| Endpoint | Method | Description |
|----------|--------|-------------|
| /health | GET | Server status |
| /v1/auth/register | POST | Create account |
| /v1/auth/login | POST | Login (sends 2FA code) |
| /v1/auth/verify-code | POST | Verify 2FA code → get API key |
| /v1/agents | POST | Register agent |
| /v1/agents | GET | List agents |
| /v1/agents/:did | GET | Agent details + trust score |
| /v1/events | POST | Track event |
| /v1/events/batch | POST | Track up to 500 events |
| /v1/webhooks | POST | Register webhook alert |

## Trust Score

Every agent has a trust score from 0 to 100:

| Score | Level | Meaning |
|-------|-------|---------|
| 80-100 | TRUSTED ✅ | Agent behaves correctly |
| 50-79 | NEUTRAL ⚠️ | Some issues detected |
| 0-49 | UNTRUSTED ❌ | Significant problems found |

Score changes per event:
- `+1` successful action
- `-1` error outcome
- `-5` anomaly detected
- `-100` scope violation or hardware conflict

## Webhook Alerts

Get notified instantly when something suspicious happens:

```bash
curl -X POST https://aria-production-0458.up.railway.app/v1/webhooks \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-server.com/alerts"}'
```

ARIA will POST to your URL within seconds of any anomaly:

```json
{
  "alert": "TRUST_SCORE_CRITICAL",
  "severity": "CRITICAL",
  "agent": {
    "did": "did:agentrust:...",
    "name": "your-agent",
    "trustScore": 0
  },
  "reason": "scope_violation",
  "timestamp": "2026-04-27T..."
}
```

## Security

- **HMAC-SHA256** signature verification on every event
- **DTS** (Distributed Trust Shell) — Shamir Secret Sharing + Hardware Fingerprint binding
- **AES-256-GCM** encryption for secrets at rest
- **ARIA Membrane** — single entry/exit point, IP blocking, silent failure on suspicious paths
- **Replay attack protection** — 5-minute timestamp window + eventId nonce
- **Rate limiting** — Redis-backed shared state across all instances
- **2FA** — email verification code on every login
- **Security audit: 85/86 (99%)**

## Cryptographic Identity

Every agent gets a permanent decentralized identifier: Compatible with W3C DID standard. Immutable. Unforgeable.

## Roadmap

- [x] Phase 1 — MVP: DID, HMAC, reputation, audit trail
- [x] Phase 2 — Production: Dashboard, 2FA, webhooks, Redis, Membrane
- [ ] Phase 3 — ARIA Spectrum: Universal event receiver, behavioral fingerprinting
- [ ] Phase 4 — ARIA Temporal Anchor: RFC 3161 cryptographic time proofs
- [ ] Phase 5 — ARIA ZeroProof: Zero-knowledge behavioral compliance proofs

## License

BUSL-1.1 — Source available. Commercial use requires agreement.

## Stack

Node.js · Express · TypeScript · PostgreSQL · Redis · Railway

## Links

- GitHub: https://github.com/ariatrust-io/aria
- npm: https://www.npmjs.com/package/@ariatrust-io/aria-sdk
- Dashboard: https://aria-production-0458.up.railway.app/app

---

*Verified by Design · Trusted by Architecture*

<environment_details>
Current time: 2026-04-27T01:11:01-05:00
</environment_details>
