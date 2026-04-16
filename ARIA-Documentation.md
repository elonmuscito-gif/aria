# ARIA - Autonomous Reliable Intelligent Agents

## Overview

ARIA is a Node.js/Express/TypeScript server that provides a trust and auditing system for AI agents. It tracks agent activities, verifies cryptographic signatures, calculates reputation scores, and detects anomalies. The system is designed to ensure that AI agents operate within their defined scope and are who they claim to be.

---

## Architecture Components

### 1. Main Server Entry Point (`src/index.ts`)

**Purpose:** Main application entry point that configures Express, sets up middleware, defines public routes, and starts the HTTP server.

**Key Functions:**

- **Error Handling:** 
  - `process.on("uncaughtException")` - Catches fatal uncaught exceptions and exits the process
  - `process.on("unhandledRejection")` - Catches unhandled promise rejections and exits the process
  
- **Middleware Configuration:**
  - `helmet()` - Security headers (CSP disabled for development)
  - `cors()` - Cross-Origin Resource Sharing enabled
  - `express.json({ limit: "1mb" })` - Parses JSON bodies with 1MB limit
  - `rateLimit()` - Express-rate-limit configured to 1500 requests per minute per IP

- **Public Routes:**
  - `POST /v1/setup` - Initial setup endpoint for new users to create their first API key and agent (Chicken-and-Egg solution). Accepts `owner_email`, `setup_key`, `name`, and `scope`. Returns `api_key` and optionally `agent` object with `did`, `name`, `scope`, and `secret`.

- **Protected Routes:**
  - `POST /v1/agents` - Requires API key authentication via Bearer token
  - `GET /v1/agents` - Lists all agents for the authenticated API key
  - `GET /v1/agents/:did` - Gets detailed information about a specific agent
  - `POST /v1/events` - Records a single event from an agent
  - `POST /v1/events/batch` - Records multiple events in a single request
  - `GET /v1/events` - Lists events with filtering by agent, outcome, and pagination

- **Health Check:**
  - `GET /health` - Returns server status and database connection state

- **Error Handlers:**
  - 404 handler for undefined routes
  - Global error handler for unhandled errors

- **Server Startup:**
  - Listens on port 3001 (or PORT environment variable)
  - Logs server start message with environment

---

### 2. Database Connection Pool (`src/db/pool.ts`)

**Purpose:** Manages PostgreSQL connection pooling and provides query utilities.

**Key Components:**

- **Pool Configuration:**
  - `max: 50` - Maximum number of connections in the pool
  - `statement_timeout: 10,000ms` - Queries timeout after 10 seconds
  - `idleTimeoutMillis: 30,000ms` - Connections idle for 30 seconds are closed
  - `connectionTimeoutMillis: 2,000ms` - Connection attempts timeout after 2 seconds
  - `ssl: { rejectUnauthorized: true }` - SSL required for production, disabled for local

- **Functions:**
  - `query(text, values)` - Executes a SQL query and returns results typed generically
  - `transaction(fn)` - Executes a function within a database transaction (BEGIN/COMMIT/ROLLBACK)
  - `checkHealth()` - Returns true if database is reachable, false otherwise

- **Error Handling:**
  - Pool error listener logs idle connection failures without crashing the server

---

### 3. Authentication Middleware (`src/middleware/auth.ts`)

**Purpose:** Protects API routes by validating API keys stored in the database.

**Key Components:**

- **API Key Cache:**
  - `keyCache` - In-memory Map storing validated API keys
  - `CACHE_TTL_MS: 300,000` - Cache entries expire after 5 minutes
  - `MAX_CACHE_SIZE: 10,000` - Maximum number of cached keys to prevent memory leaks

- **Cache Management:**
  - `cleanExpiredCache()` - Removes expired entries from the cache

- **Authentication Flow (`requireApiKey` function):**
  1. Extracts Bearer token from Authorization header
  2. Returns 401 if no key provided
  3. Checks cache first (O(1) fast path) - if cache hit, sets `req.apiKeyId` and `req.ownerEmail`, calls `next()`
  4. If not cached, computes SHA-256 hash of the key
  5. **Fast Path:** Queries `api_keys` table by `key_sha256` index
     - If found, verifies with bcrypt.compare against `key_hash`
     - On success, caches the key and proceeds
     - On failure (bcrypt mismatch), returns 401 immediately (prevents timing attacks)
  6. **Slow Path (Legacy):** If no SHA-256 match, searches legacy keys without SHA-256 (limited to 50 for DoS protection)
     - On match, updates the key with SHA-256 (self-heal) and caches it
  7. Returns 401 if no valid key found
  8. Returns 500 if database error occurs

- **Request Augmentation:**
  - Adds `apiKeyId` to `req` - The UUID of the API key
  - Adds `ownerEmail` to `req` - The email of the key owner

---

### 4. Agents Routes (`src/routes/agents.ts`)

**Purpose:** Handles agent registration, listing, and retrieval.

**Key Routes:**

- **POST /** - Register a new agent
  - **Input:** `name` (string, required), `scope` (array of strings, required), `hardwareFingerprint` (optional), `meta` (optional object)
  - **Validation:** 
    - Name must be non-empty string
    - Scope must be non-empty array
    - Each scope item must match pattern `verb:resource` (e.g., "send:email")
  - **Credential Generation (Two Modes):**
    - **Classic Mode:** If no `hardwareFingerprint` provided:
      - Generates `secret` as two UUIDs concatenated without dashes
      - Sets `signingVersion` to 1
      - Hashes secret with bcrypt (cost 10)
      - Returns `secret` to the client (used for HMAC signing)
    - **DTS (Distributed Trusted Signing) Mode:** If `hardwareFingerprint` provided:
      - Generates 32 random bytes as the master secret
      - Splits secret into 3 shares using Shamir's Secret Sharing (threshold: 2)
      - Derives `partialAKey` from shareA using HKDF-SHA256
      - Hashes shareB with bcrypt
      - Sets `signingVersion` to 2
      - Returns `fragmentB` (shareB in hex) and `partialAKey` to the client
  - **Output:** Returns `did` (format: `did:agentrust:<uuid>`), `name`, `scope`, `createdAt`, `publicKey`, and the credential (`secret` or `fragmentB`/`partialAKey`)

- **GET /** - List all agents for the authenticated API key
  - **Output:** Returns array of agents with `name`, `masked_did`, `scope_summary`, `scope_count`, `created_at`, `last_seen`, `total_events`, `anomaly_count`, `success_rate`

- **GET /:did** - Get detailed information about a specific agent
  - **Output:** Returns full agent details including `did`, `name`, `scope`, `created_at`, `last_seen`, `meta` (whitelisted keys only: simulated, version, environment, region), `total_events`, `success_count`, `error_count`, `anomaly_count`, `success_rate`, `top_actions`

---

### 5. Events Routes (`src/routes/events.ts`)

**Purpose:** Handles event ingestion, validation, signature verification, anomaly detection, and event listing.

**Key Components:**

- **Rate Limiting (Per-Agent):**
  - `rateLimitMap` - Map tracking request counts per agent
  - `RATE_LIMIT_WINDOW_MS: 60,000` - 1-minute window
  - `RATE_LIMIT_MAX: 100` - Maximum 100 events per window
  - If exceeded, events are accepted but flagged in metadata

- **Event Interface (`IncomingEvent`):**
  - `eventId` - Unique identifier for the event
  - `agentDid` - The agent's DID (must start with "did:agentrust:")
  - `action` - The action performed (e.g., "send:email")
  - `outcome` - "success", "error", or "anomaly"
  - `withinScope` - Boolean indicating if action was within declared scope
  - `durationMs` - Duration in milliseconds
  - `timestamp` - ISO 8601 timestamp
  - `signature` - Cryptographic signature
  - `error` (optional) - Error message if outcome is "error"
  - `meta` (optional) - Additional metadata

- **Validation Function (`validateEvent`):**
  - Validates all required fields
  - Returns error message if invalid, null if valid

- **Signature Verification (`determineSignatureValidity`):**
  - **Version 1 (Classic):** HMAC-SHA256 of payload
    - Payload format: `${eventId}:${agentDid}:${action}:${outcome}:${timestamp}`
    - Uses `timingSafeEqual` to prevent timing attacks
  - **Version 2 (DTS):** XOR of two HMACs
    - Derives `partial_A` from `partialAKey` using HKDF
    - Gets `partial_B` from event meta
    - XORs both to get expected signature

- **Anomaly Detection:**
  - **Hardware Fingerprint Mismatch:** Compares event's fingerprint with stored agent fingerprint
  - **Missing Fingerprint:** Checks if event lacks hardware fingerprint
  - **Rate Limit Exceeded:** Flags events when agent exceeds rate limit
  - Calls `recordAnomaly()` to log anomalies in the anomalies table

- **Key Routes:**

  - **POST /** - Record a single event
    - Validates event structure
    - Looks up agent by DID and API key
    - Verifies scope (checks if action is in declared scope)
    - Verifies signature
    - Checks rate limits
    - Detects anomalies
    - Inserts into `events` table
    - Updates agent's `last_seen` timestamp
    - Queues reputation recalculation
    - Returns 202 Accepted

  - **POST /batch** - Record multiple events (max 500)
    - Validates array is non-empty and <= 500
    - Looks up agent once
    - Processes each event in a database transaction
    - Tracks accepted vs rejected counts
    - Returns summary of accepted/rejected events

  - **GET /** - List events
    - Filters by `agentDid`, `outcome`
    - Supports pagination via `limit` (default 50, max 200) and `cursor`
    - Returns events with agent information

---

### 6. Reputation Service (`src/services/reputation.ts`)

**Purpose:** Calculates and maintains agent reputation scores based on their event history.

**Key Components:**

- **ReputationQueue:**
  - Debounces recalculation by 3 seconds
  - Batches multiple agent updates
  - Retries failed calculations (except connection errors)

- **Reputation Calculation (`computeReputationIncremental`):**
  - Gets events since last computation (or all if first time)
  - Aggregates: `total_events`, `success_count`, `error_count`, `anomaly_count`, `scope_violation_count`, `hardware_conflict_count`
  - Computes `success_rate` as percentage
  - Updates `reputation_snapshots` table

- **Scoring Algorithm:**
  - `successPoints` = success_count × 1
  - `errorPoints` = error_count × -1
  - `anomalyPoints` = anomaly_count × -5
  - `criticalPoints` = (scope_violation_count + hardware_conflict_count) × -100
  - `finalScore` = clamped between 0 and 100
  - **Trust Levels:**
    - Score >= 80: "Trusted"
    - Score >= 50: "Neutral"
    - Score < 50: "Untrusted"

- **Sync:** Calls `syncToPublicTable()` to update the public reputation table

---

### 7. Public Reputation Sync (`src/services/sync-public-reputation.ts`)

**Purpose:** Synchronizes internal reputation data to a publicly accessible table for web/API access.

**Key Function (`syncToPublicTable`):**
- Takes agent ID and score
- Determines trust level based on score
- Upserts into `public_agent_reputation` table
- Non-critical - errors are logged but don't fail the main flow

---

### 8. Anomaly Detector (`src/services/anomaly-detector.ts`)

**Purpose:** Records and manages anomalies detected during event processing.

**Key Components:**

- **Storage Limits:**
  - `MAX_ANOMALIES_PER_AGENT: 100` - Maximum anomalies stored per agent
  - Prevents disk saturation from malicious agents

- **Record Function (`recordAnomaly`):**
  - Checks current anomaly count for the agent
  - Skips recording if at limit (event already in events table)
  - Inserts into `anomalies` table if space available
  - Non-critical - logs errors but doesn't throw

- **Cleanup Function (`cleanupOldAnomalies`):**
  - Deletes anomalies older than 30 days
  - Deletes acknowledged anomalies
  - Designed to be run via cron job

---

## Database Schema (Tables)

### api_keys
- `id` (UUID, PK)
- `key_hash` (TEXT) - bcrypt hash of the API key
- `key_sha256` (TEXT) - SHA-256 hash for fast lookups
- `label` (TEXT) - Human-readable label
- `owner_email` (TEXT) - Owner's email
- `created_at` (TIMESTAMPTZ)
- `revoked_at` (TIMESTAMPTZ, nullable)

### agents
- `id` (UUID, PK)
- `did` (TEXT, unique)
- `name` (TEXT)
- `scope` (TEXT[]) - Array of scope actions
- `api_key_id` (UUID, FK to api_keys)
- `public_key` (TEXT)
- `secret_hash` (TEXT) - bcrypt hash of the signing secret
- `hmac_key` (TEXT) - The actual HMAC key (hex encoded)
- `meta` (JSONB)
- `signing_version` (INT) - 1 for classic, 2 for DTS
- `created_at` (TIMESTAMPTZ)
- `last_seen` (TIMESTAMPTZ, nullable)

### events
- `id` (UUID, PK)
- `event_id` (TEXT, unique)
- `agent_id` (UUID, FK to agents)
- `action` (TEXT)
- `outcome` (TEXT) - 'success', 'error', 'anomaly'
- `within_scope` (BOOLEAN)
- `duration_ms` (INT)
- `signature` (TEXT)
- `signature_valid` (BOOLEAN)
- `error` (TEXT, nullable)
- `meta` (JSONB, nullable)
- `recorded_at` (TIMESTAMPTZ)
- `client_ts` (TIMESTAMPTZ)
- `server_within_scope` (BOOLEAN)

### reputation_snapshots
- `agent_id` (UUID, PK, FK to agents)
- `total_events` (INT)
- `success_count` (INT)
- `error_count` (INT)
- `anomaly_count` (INT)
- `scope_violation_count` (INT)
- `hardware_conflict_count` (INT)
- `success_rate` (TEXT)
- `top_actions` (JSONB)
- `last_computed_at` (TIMESTAMPTZ)

### public_agent_reputation
- `did` (TEXT, PK)
- `score` (INT)
- `trust_level` (TEXT)
- `last_updated` (TIMESTAMPTZ)

### anomalies
- `id` (UUID, PK)
- `event_id` (TEXT)
- `agent_id` (UUID, FK to agents)
- `action` (TEXT)
- `detected_at` (TIMESTAMPTZ)
- `acknowledged` (BOOLEAN, default false)

---

## Security Features

1. **API Key Authentication:** All protected routes require valid API key via Bearer token
2. **Double Hashing:** Keys stored with both SHA-256 (for fast lookup) and bcrypt (for verification)
3. **Timing-Safe Comparison:** Prevents timing attacks on signature verification
4. **Rate Limiting:** Per-IP (1500/min) and per-agent (100/min) rate limits
5. **Input Validation:** All inputs validated before processing
6. **Scope Validation:** Server independently verifies if actions are in declared scope
7. **Signature Verification:** Cryptographic verification of event authenticity
8. **Hardware Fingerprint Tracking:** Detects when events come from different machines
9. **Anomaly Rate Limiting:** Prevents disk saturation from anomaly storage
10. **SQL Parameterization:** All queries use parameterized statements to prevent injection

---

## Setup Flow (Chicken-and-Egg Solution)

1. **New User:** Calls `POST /v1/setup` with:
   - `owner_email` - Their email
   - `setup_key` - Master key (from environment or default "aria-setup-2024")
   - `name` (optional) - Agent name
   - `scope` (optional) - Agent scope array

2. **Server:**
   - Validates setup key
   - Checks no existing API key for that email
   - Generates new API key (UUID)
   - Hashes with SHA-256 and stores
   - Creates agent if name/scope provided
   - Returns API key and agent credentials

3. **Client:** Uses returned API key in Authorization header for all subsequent requests

---

## Environment Variables

- `PORT` - Server port (default: 3001)
- `DATABASE_URL` - PostgreSQL connection string (required)
- `NODE_ENV` - "development" or "production"
- `SETUP_KEY` - Master key for initial setup (default: "aria-setup-2024")

---

## Technology Stack

- **Runtime:** Node.js
- **Language:** TypeScript
- **Framework:** Express.js 5.x
- **Database:** PostgreSQL with pg driver
- **Security:** bcrypt, crypto (HMAC-SHA256, HKDF, Shamir's Secret Sharing)
- **Rate Limiting:** express-rate-limit
- **Security Headers:** helmet
- **TypeScript Execution:** tsx