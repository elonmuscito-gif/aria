# ARIA — Autonomous Registry for Intelligence Accountability

> Trust infrastructure for AI agents. Every agent gets a cryptographic identity, an immutable audit trail, and a reputation score.

## What is ARIA?

ARIA is the accountability layer the AI industry is missing. Companies deploy AI agents that act on their behalf — sending emails, processing payments, accessing databases. ARIA makes those agents auditable, verifiable, and trustworthy.

## How it works

1. **Register** your agent with a name and declared scope
2. **Track** every action with `agent.track()` — ARIA signs and verifies
3. **Prove** compliance with a cryptographic audit trail

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

// Register your agent
const agent = await aria.registerAgent({
  name: 'invoice-processor',
  scope: ['read:invoices', 'write:invoices']
});

// Track every action
await aria.track(agent.did, agent.secret, 'read:invoices', async () => {
  // your agent logic here
});
```

## API

Base URL: `https://aria-production-0458.up.railway.app`

| Endpoint | Method | Description |
|----------|--------|-------------|
| /health | GET | Server status |
| /v1/auth/register | POST | Create account |
| /v1/auth/login | POST | Login |
| /v1/agents | POST | Register agent |
| /v1/agents | GET | List agents |
| /v1/events | POST | Track event |
| /v1/events/batch | POST | Track up to 500 events |

## Security

- HMAC-SHA256 signature verification on every event
- Server-side scope revalidation independent of agent reports
- DTS (Distributed Trust Shell) — Shamir Secret Sharing + Hardware Fingerprint
- AES-256-GCM encryption for secrets at rest
- ARIA Membrane — single entry/exit point, IP blocking, silent failure

## License

BUSL-1.1 — Source available. Commercial use requires agreement.

## Stack

Node.js · Express · TypeScript · PostgreSQL · Railway

## Get Started

Create your account and get an API key:

```bash
curl -X POST https://aria-production-0458.up.railway.app/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@company.com","password":"yourpassword","name":"Your Name"}'
```

---

Built with ❤️ for the agentic AI economy.