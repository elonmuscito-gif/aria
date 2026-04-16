# ARIA

Agent Reputation Intelligence API — A secure event ingestion and reputation tracking system for autonomous agents.

## Stack

- Node.js + Express + TypeScript + PostgreSQL

## Run Locally

```bash
# 1. Copy and configure environment
cp .env.example .env

# 2. Install dependencies
npm install

# 3. Start the server
npx tsx src/index.ts
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /v1/setup | None | Create API key and agent |
| GET | /v1/agents | API Key | List agents |
| POST | /v1/agents | API Key | Create agent |
| GET | /v1/agents/:did | API Key | Get agent details |
| POST | /v1/events | API Key | Ingest single event |
| POST | /v1/events/batch | API Key | Ingest batch of events |
| GET | /v1/events | API Key | List events |
| GET | /health | None | Health check |

## License

BUSL-1.1