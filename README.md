# ARIA — Autonomous Registry for Intelligence Accountability

Trust infrastructure for autonomous AI. Every agent gets a cryptographic identity, an immutable audit trail, and a dynamic reputation score.

## The Problem

Companies are deploying AI agents that execute real-world actions: sending emails, processing payments, modifying databases. If an agent goes out of bounds, who is liable? **ARIA is the accountability layer the AI industry is missing.** It makes agent actions cryptographically auditable, scope-enforced, and compliant.

## How It Works

1. **Declare Scope:** Register your agent with explicitly allowed actions (e.g., `read:invoices`).
2. **Sign Actions:** Use `aria.track()` to wrap agent logic. ARIA signs the payload server-side.
3. **Enforce & Audit:** The server independently re-validates the scope and stores an immutable audit trail.
4. **Monitor Trust:** Track agent success rates, anomalies, and scope violations in real-time.

## Quick Start

```bash
npm install @elonmuscito/aria-sdk
```

```typescript
import { createClient } from '@elonmuscito/aria-sdk';

const aria = createClient({
  baseUrl: 'https://aria-production-0458.up.railway.app',
  apiKey: 'your-api-key'
});

// Register a classic agent
const agent = await aria.registerAgent({
  name: 'invoice-processor',
  scope: ['read:invoices', 'write:invoices']
});

// Track every action
await aria.track(agent.did, agent.secret, 'read:invoices', async () => {
  // your agent logic here
});
```

## Advanced Security: DTS (Distributed Trust Shell)

For high-risk environments, standard API keys are insufficient. If the server is compromised, the attacker gets full access.

**DTS** uses **Shamir's Secret Sharing** bound to a **hardware fingerprint** so the complete secret **never exists** in server RAM or the database.

```typescript
import { createClient } from '@elonmuscito/aria-sdk';

const aria = createClient({
  baseUrl: 'https://aria-production-0458.up.railway.app',
  apiKey: 'your-api-key'
});

// Register with hardware-bound DTS agent
const agent = await aria.registerAgent({
  name: 'payment-processor',
  scope: ['process:payment', 'read:transactions'],
  hardwareFingerprint: 'a1b2c3d4e5f6...' // Client's hardware ID
});

console.log(agent.fragmentB);   // ShareB - keep safe, never share
console.log(agent.partialAKey); // partialA - server uses only
// The full secret is split: ShareA(server) + ShareB(client) + ShareC(hw_fp)
```

The client must provide `partial_b` in event metadata for signature verification. The server derives `ShareA` from its stored fragment and binds it with the client's `partial_b` using HMAC — the original secret is never reconstructed.

## API Reference

Base URL: `https://aria-production-0458.up.railway.app`

| Endpoint | Method | Description |
|----------|--------|-------------|
| /health | GET | Server status |
| /v1/auth/register | POST | Create account |
| /v1/auth/login | POST | Login |
| /v1/agents | POST | Register agent |
| /v1/agents | GET | List agents |
| /v1/agents/:did | GET | Agent detail |
| /v1/events | POST | Track event |
| /v1/events/batch | POST | Track up to 500 events |

## Enterprise Security Model

- **HMAC-SHA256 Signatures:** Every event is signed and verified server-side
- **Zero-Trust Scope Enforcement:** Server recalculates permissions independently, client claims are ignored
- **AES-256-GCM at Rest:** Encryption with random IVs and auth tags for stored secrets
- **ARIA Membrane:** Single entry/exit point, IP blocking, silent failure on blocked paths

## License

BUSL-1.1 — Source available. Commercial use requires agreement.

## Stack

Node.js · Express · TypeScript · PostgreSQL · Railway

## Get Started

```bash
curl -X POST https://aria-production-0458.up.railway.app/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@company.com","password":"yourpassword","name":"Your Name"}'
```

---

Built with ❤️ for the Agentic AI Economy.