# ARIA — Autonomous Registry for Intelligence Accountability

> The trust and enforcement infrastructure for AI agents.
> Observe what agents do. Control what agents are allowed to do.

## What is ARIA?

ARIA is the accountability layer the AI industry is missing. Companies deploy AI agents that act on their behalf — sending emails, processing payments, accessing databases. ARIA makes those agents auditable, verifiable, and trustworthy.

---

## Quick Start

### 1. Create your account

Go to [ariatrust.org/app](https://ariatrust.org/app) and register.

After confirming your email and signing in, copy your **API Key** from the dashboard.

### 2. Install the SDK

```bash
npm install @ariatrust-io/aria-sdk
```

### 3. Register your agent

```typescript
import { createClient } from '@ariatrust-io/aria-sdk';

const aria = createClient({
  baseUrl: 'https://ariatrust.org',
  apiKey: 'your-api-key-from-dashboard'
});

// Register your agent with a name and declared scope
const agent = await aria.registerAgent({
  name: 'invoice-processor',
  scope: ['read:invoices', 'write:invoices', 'send:email']
});

console.log(agent.did);    // did:agentrust:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
console.log(agent.secret); // keep this safe — used to sign events
```

### 4. Track every action

```typescript
const result = await aria.track(
  agent.did,
  agent.secret,
  'read:invoices',
  async () => {
    // your agent logic here
    return await fetchInvoices();
  }
);

console.log(result.insights);
// {
//   scope:      { valid: true, attempted: 'read:invoices' },
//   signature:  { valid: true },
//   rateLimit:  { exceeded: false, current: 1, limit: 100, resetsIn: '59s' },
//   trustScore: { impact: +1 }
// }
```

### 5. View your agent in the dashboard

Sign in at `https://ariatrust.org/app` and see:
- Live trust score and trust level
- Full event history
- Anomalies detected
- API key management

---

## Trust Score

Every agent has a trust score from **0 to 100**:

| Score | Level | Meaning |
|-------|-------|---------|
| 80 – 100 | ✅ TRUSTED | Agent behaves correctly |
| 50 – 79 | ⚠️ NEUTRAL | Some issues detected |
| 0 – 49 | ❌ UNTRUSTED | Significant problems found |

**Score changes per event:**

| Event | Impact |
|-------|--------|
| Successful action | +1 |
| Error outcome | -1 |
| Anomaly detected | -5 |
| Scope violation | -100 |
| Hardware conflict | -100 |

Scores decay toward neutral (50) if the agent is inactive for 7+ days.

---

## Webhook Alerts

Get notified instantly when something suspicious happens:

```bash
curl -X POST https://ariatrust.org/v1/webhooks \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-server.com/aria-alerts",
    "events": ["anomaly", "scope_violation", "trust_score_critical"]
  }'
```

ARIA will POST to your URL within seconds:

```json
{
  "alert": "TRUST_SCORE_CRITICAL",
  "severity": "CRITICAL",
  "agent": {
    "did": "did:agentrust:...",
    "name": "invoice-processor",
    "trustScore": 0
  },
  "reason": "scope_violation",
  "timestamp": "2026-04-28T16:00:43.497Z"
}
```

Each webhook is signed with HMAC-SHA256 via the `X-ARIA-Signature` header so you can verify it came from ARIA.

---

## API Reference

**Base URL:** `https://ariatrust.org`

### Authentication

All API requests require a Bearer token:

```http
Authorization: Bearer your-api-key
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server status and DB connectivity |
| POST | `/v1/auth/register` | Create a user account |
| POST | `/v1/auth/login` | Sign in (sends 2FA code) |
| POST | `/v1/auth/verify-code` | Verify 2FA code → receive API key |
| POST | `/v1/agents` | Register a new agent |
| GET | `/v1/agents` | List your agents |
| GET | `/v1/agents/:did` | Get agent details and trust score |
| POST | `/v1/events` | Track a single event |
| POST | `/v1/events/batch` | Track up to 500 events |
| GET | `/v1/events` | List events |
| POST | `/v1/webhooks` | Register a webhook alert URL |
| GET | `/v1/webhooks` | List your webhooks |
| DELETE | `/v1/webhooks/:id` | Remove a webhook |
| POST | `/v1/api-keys` | Create a new API key |
| POST | `/v1/api-keys/rotate` | Rotate your API key |

---

## Security

ARIA was built security-first and passed a **86/86 internal security audit**.

| Feature | Implementation |
|---------|----------------|
| Event signing | HMAC-SHA256 with `timingSafeEqual` |
| Secrets at rest | AES-256-GCM with context binding (AAD) |
| DTS | Distributed Trust Shell — Shamir Secret Sharing + Hardware Fingerprint |
| Network shield | ARIA Membrane — single entry point, IP blocking, silent failure |
| Replay protection | 5-minute timestamp window + eventId nonce |
| Rate limiting | Redis-backed, shared across all instances |
| Authentication | Email + 2FA verification code |
| Input validation | Field limits, JSON depth protection, Content-Type enforcement |

---

## Cryptographic Identity

Every agent receives a permanent decentralized identifier:

```
did:agentrust:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

This identifier is:
- **Permanent** — never changes
- **Immutable** — cannot be altered retroactively
- **Verifiable** — cryptographically tied to the agent's secret and hardware

---

## What's Coming

ARIA is built in two layers:

**ARIA Core** (available now) — Observability & Trust
Identity, audit trail, reputation scoring, anomaly detection.

**ARIA Gate** (in development) — Control & Enforcement
Runtime policy enforcement that stops destructive actions
before they execute.

---

### ARIA Gate — Runtime Enforcement for AI Agents

Most monitoring systems observe and record what agents do.
ARIA Gate enforces what agents are allowed to do — at runtime,
before execution reaches external systems.

**How it works**

ARIA Gate operates as an execution proxy placed between
the agent and the systems it interacts with.
All agent actions must pass through ARIA before reaching
external systems. ARIA enforces policies at runtime by
allowing, delaying, or blocking execution.
**Enforcement is guaranteed when ARIA is placed
in the execution path.** Agents that bypass ARIA
have no audit trail — which is itself a detectable anomaly.

**Risk classification**

| Action | Risk Level | Enforcement |
|--------|-----------|-------------|
| `delete:*` | CRITICAL | Block + human approval required |
| `drop:*` | CRITICAL | Block + human approval required |
| `transfer:funds` | CRITICAL | Block + human approval required |
| `export:bulk` | HIGH | Alert + 60 second delay |
| `modify:permissions` | HIGH | Block + human approval required |
| `send:bulk_email` | MEDIUM | Alert + approval |
| `read:bulk` | LOW | Log + monitor |

These policies live in ARIA — not in the agent's code.
Developers declare them at registration time.
Agents cannot modify their own policies.

**On the PocketOS incident (April 2026)**

An AI agent deleted an entire production database and its
backups — causing millions in damages.

With ARIA Gate in the execution path, `delete:database`
would have required explicit human approval before execution,
preventing the automatic deletion from occurring.

---

### ARIA Shadow Witness — Independent Verification

An agent can report anything. ARIA Shadow Witness verifies
it actually happened — by asking independent sources.

**How it works**
An agent that misreports its actions cannot simultaneously
fool the independent witness. The discrepancy is detectable,
recordable, and provable in court.

**Supported witness types**

| Witness | What it verifies |
|---------|-----------------|
| Payment processors | Transactions actually occurred |
| Email providers | Messages actually delivered |
| Databases | Records actually created or modified |
| External APIs | Calls actually made and responses received |
| Time authorities | Actions occurred at the claimed timestamp |

**Why this matters for compliance**

Traditional audit systems trust agent-reported data.
ARIA Shadow Witness introduces a second, independent source
of truth — making it cryptographically difficult for an agent
to fabricate its activity history without detection.

---

## Roadmap

- [x] **Phase 1** — Core: Cryptographic DID, HMAC event signing, reputation scoring, audit trail
- [x] **Phase 2** — Production: Dashboard, 2FA auth, webhooks, Redis, ARIA Membrane, security hardening (86/86 audit)
- [ ] **Phase 3** — ARIA Spectrum: Universal event receiver, behavioral fingerprinting, cross-verification protocol
- [ ] **Phase 4** — ARIA Gate: Runtime enforcement, human approval flows, risk classification, auto-blocking
- [ ] **Phase 5** — ARIA Shadow Witness: Independent verification of agent-reported actions
- [ ] **Phase 6** — ARIA Temporal Anchor: RFC 3161 cryptographic time proofs anchored to international time authorities
- [ ] **Phase 7** — ARIA ZeroProof: Zero-knowledge behavioral compliance proofs — prove correct behavior without revealing business data

---

## Self-Hosting

ARIA is open source under BUSL-1.1. You can run it yourself:

```bash
git clone https://github.com/ariatrust-io/aria.git
cd aria/server
npm install
cp .env.example .env
# Fill in your environment variables
npm start
```

**Required environment variables:**

```env
DATABASE_URL=postgresql://user:password@host:5432/dbname
ENCRYPTION_KEY=your-32-byte-hex-key
SETUP_KEY=your-secure-random-key
RESEND_API_KEY=your-resend-api-key
APP_URL=https://your-domain.com
REDIS_URL=redis://localhost:6379
ALLOWED_ORIGINS=https://your-domain.com
```

---

## Stack

Node.js · TypeScript · Express · PostgreSQL · Redis · Railway

---

## Links

- **Dashboard:** https://ariatrust.org/app
- **npm SDK:** https://www.npmjs.com/package/@ariatrust-io/aria-sdk
- **GitHub:** https://github.com/ariatrust-io/aria

---

## License

**BUSL-1.1** — Source available. Free for non-commercial use.
Commercial use requires a license agreement.

---

*Verified by Design · Trusted by Architecture*
