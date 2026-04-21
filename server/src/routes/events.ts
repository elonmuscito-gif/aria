import { Router } from "express";
import { createHmac, hkdfSync, timingSafeEqual } from "crypto";
import { query, transaction } from "../db/pool.js";
import { requireApiKey } from "../middleware/auth.js";
import { reputationQueue } from "../services/reputation.js";
import { recordAnomaly } from "../services/anomaly-detector.js";
import { decryptSecret } from "../utils/crypto.js";

const SENSITIVE_META_FIELDS = [
  'hardwareFingerprint',
  'expected_fp',
  'received_fp',
  'signatureInvalid',
  'partial_b',
  'partialAKey',
  'rate_limit_exceeded',
  'dts_share_c',
];

function sanitizeMeta(meta: Record<string, unknown> | null) {
  if (!meta) return meta;
  const clean = { ...meta };
  for (const field of SENSITIVE_META_FIELDS) {
    delete clean[field];
  }
  return clean;
}

const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 100;

function checkRateLimit(agentId: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(agentId);
  
  if (!entry || now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(agentId, { count: 1, windowStart: now });
    return false;
  }
  
  entry.count++;
  
  if (entry.count > RATE_LIMIT_MAX * 10) {
    rateLimitMap.set(agentId, { count: 1, windowStart: now });
    return false;
  }

  return entry.count > RATE_LIMIT_MAX;
}

function getRateLimitInfo(agentId: string): { exceeded: boolean; current: number; limit: number; resetsIn: string } {
  const entry = rateLimitMap.get(agentId);
  const now = Date.now();
  
  if (!entry) {
    return { exceeded: false, current: 0, limit: RATE_LIMIT_MAX, resetsIn: "60s" };
  }
  
  const current = entry.count > RATE_LIMIT_MAX ? entry.count - RATE_LIMIT_MAX : entry.count;
  const resetsInMs = (entry.windowStart + RATE_LIMIT_WINDOW_MS) - now;
  const resetsIn = `${Math.ceil(Math.max(0, resetsInMs) / 1000)}s`;
  
  return {
    exceeded: entry.count > RATE_LIMIT_MAX,
    current,
    limit: RATE_LIMIT_MAX,
    resetsIn
  };
}

export const eventsRouter = Router();

eventsRouter.use(requireApiKey);

interface IncomingEvent {
  eventId: string;
  agentDid: string;
  action: string;
  outcome: "success" | "error" | "anomaly";
  withinScope: boolean;
  durationMs: number;
  timestamp: string;
  signature: string;
  error?: string;
  meta?: Record<string, unknown>;
}

interface AgentSignatureContext extends Record<string, unknown> {
  apiKeyId: string;
  eventId: string;
  agentDid: string;
  action: string;
}

function logEvent(level: "log" | "warn" | "error", message: string, context?: Record<string, unknown>): void {
  const payload = context ? ["[events]", message, context] : ["[events]", message];
  console[level](...payload);
}

function summarizeEvent(event: Partial<IncomingEvent>): Record<string, unknown> {
  return {
    eventId: event.eventId,
    agentDid: event.agentDid,
    action: event.action,
    outcome: event.outcome,
    withinScope: event.withinScope,
    durationMs: event.durationMs,
    timestamp: event.timestamp,
    hasError: typeof event.error === "string" && event.error.length > 0,
    metaKeys: event.meta ? Object.keys(event.meta) : [],
  };
}

function determineSignatureValidity(
  event: IncomingEvent,
  hmacKey: string | null,
  signingVersion: number,
  context: AgentSignatureContext,
): boolean {
  if (hmacKey === null) {
    logEvent("warn", "Signature not verified: agent was registered before HMAC key support", context);
    return false;
  }

  if (signingVersion === 2) {
    const signatureValid = verifySignatureV2(event, hmacKey);
    if (!signatureValid) {
      logEvent("warn", "DTS signature verification failed: XOR(partial_A, partial_B) does not match event.signature", context);
    }
    return signatureValid;
  }

  const signatureValid = verifySignatureV1(event, hmacKey);
  if (!signatureValid) {
    logEvent("warn", "Signature verification failed: event signature does not match expected HMAC", context);
  }
  return signatureValid;
}

eventsRouter.post("/", async (req, res) => {
  const event = req.body as IncomingEvent;
  logEvent("log", "Received single event ingestion request", {
    apiKeyId: req.apiKeyId,
    event: summarizeEvent(event),
  });

  const validationError = validateEvent(event);
  if (validationError) {
    logEvent("warn", "Rejected single event due to validation error", {
      apiKeyId: req.apiKeyId,
      validationError,
      event: summarizeEvent(event),
    });
    return res.status(400).json({ error: validationError, code: "INVALID_EVENT" });
  }

  try {
    logEvent("log", "Starting single event ingestion", {
      apiKeyId: req.apiKeyId,
      eventId: event.eventId,
      agentDid: event.agentDid,
    });
    const ingestionResult = await ingestEvent(event, req.apiKeyId);
    logEvent("log", "Accepted single event", {
      apiKeyId: req.apiKeyId,
      eventId: event.eventId,
      agentDid: event.agentDid,
    });

    const insights = {
      scope: {
        valid: ingestionResult.serverWithinScope,
        attempted: event.action,
        declared: ingestionResult.scope,
        message: !ingestionResult.serverWithinScope 
          ? `Action '${event.action}' is not in declared scope`
          : `Action '${event.action}' is within declared scope`
      },
      signature: {
        valid: ingestionResult.signatureValid
      },
      rateLimit: ingestionResult.rateLimitInfo,
      trustScore: {
        impact: !ingestionResult.serverWithinScope ? -100 
          : event.outcome === 'anomaly' ? -5
          : event.outcome === 'error' ? -1 
          : 1
      }
    };

    return res.status(202).json({ 
      accepted: true, 
      eventId: event.eventId,
      insights 
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === "AGENT_NOT_FOUND") {
      logEvent("warn", "Single event rejected because agent was not found", {
        apiKeyId: req.apiKeyId,
        eventId: event.eventId,
        agentDid: event.agentDid,
      });
      return res.status(404).json({ error: "Invalid request", code: "AGENT_NOT_FOUND" });
    }
    if (err instanceof Error && err.message === "DUPLICATE_EVENT") {
      logEvent("warn", "Single event rejected because it is duplicated", {
        apiKeyId: req.apiKeyId,
        eventId: event.eventId,
        agentDid: event.agentDid,
      });
      return res.status(409).json({ error: "Invalid request", code: "DUPLICATE_EVENT" });
    }
    logEvent("error", "Unexpected error during single event ingestion", {
      apiKeyId: req.apiKeyId,
      eventId: event.eventId,
      agentDid: event.agentDid,
      error: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
});

eventsRouter.post("/batch", async (req, res) => {
  const { events } = req.body as { events?: IncomingEvent[] };
  logEvent("log", "Received batch event ingestion request", {
    apiKeyId: req.apiKeyId,
    eventCount: Array.isArray(events) ? events.length : null,
  });

  if (!Array.isArray(events) || events.length === 0) {
    logEvent("warn", "Rejected batch because payload is not a non-empty array", {
      apiKeyId: req.apiKeyId,
      receivedType: Array.isArray(events) ? "array" : typeof events,
    });
    return res.status(400).json({ error: "events must be a non-empty array", code: "INVALID_BATCH" });
  }

  if (events.length > 500) {
    logEvent("warn", "Rejected batch because it exceeds the size limit", {
      apiKeyId: req.apiKeyId,
      eventCount: events.length,
    });
    return res.status(400).json({ error: "Batch size limit is 500 events", code: "BATCH_TOO_LARGE" });
  }

  const accepted: string[] = [];
  const rejected: Array<{ eventId: string; reason: string }> = [];
  
  // Summary counters
  const summary = {
    scopeViolations: 0,
    signatureFailures: 0,
    rateLimitExceeded: 0,
    hardwareConflicts: 0
  };

  const firstEvent = events[0]!;
  const agentLookup = await query<{ id: string; scope: string[]; hmac_key: string | null; meta: Record<string, unknown> | null; signing_version: number }>(
    `SELECT id, scope, hmac_key, meta, signing_version FROM agents WHERE did = $1 AND api_key_id = $2`,
    [firstEvent.agentDid, req.apiKeyId],
  );

  if (!agentLookup.rows[0]) {
    return res.status(404).json({ error: "Invalid request", code: "AGENT_NOT_FOUND" });
  }

  const row = agentLookup.rows[0]!;
  const agentId = row.id;
  const decryptedHmacKey = row.hmac_key ? decryptSecret(row.hmac_key) : null;
  const storedShareC = typeof row.meta?.dts_share_c === "string" ? row.meta.dts_share_c : null;

  const validatedEvents: Array<{ event: typeof events[number]; serverWithinScope: boolean; signatureValid: boolean; finalMeta: Record<string, unknown> | null }> = [];

  for (const event of events) {
    const validationError = validateEvent(event);
    if (validationError) {
      rejected.push({ eventId: event.eventId ?? "unknown", reason: validationError });
      continue;
    }

    const serverWithinScope = row.scope.includes(event.action);
    const eventFp = event.meta && typeof event.meta.hardwareFingerprint === "string" ? event.meta.hardwareFingerprint : null;
    
    let hardwareConflict = false;
    if (storedShareC && eventFp) {
      const derivedShareC = Buffer.from(
        hkdfSync(
          "sha256",
          Buffer.from(eventFp, "hex"),
          Buffer.alloc(0),
          "dts_share_c_v1",
          32
        ) as ArrayBuffer
      ).toString("hex");
      if (derivedShareC !== storedShareC) {
        hardwareConflict = true;
        summary.hardwareConflicts++;
      }
    }
    
    const signatureValid = determineSignatureValidity(event, decryptedHmacKey, row.signing_version, {
      apiKeyId: req.apiKeyId,
      eventId: event.eventId,
      agentDid: event.agentDid,
      action: event.action,
    });
    
    if (!signatureValid) {
      summary.signatureFailures++;
    }

    const rateLimitExceeded = checkRateLimit(agentId);
    if (rateLimitExceeded) {
      summary.rateLimitExceeded++;
    }
    
    if (!serverWithinScope) {
      summary.scopeViolations++;
    }
    let finalMeta: Record<string, unknown> | null = rateLimitExceeded
      ? { ...event.meta, rate_limit_exceeded: true }
      : (event.meta ?? null);

    if (hardwareConflict) {
      finalMeta = { ...(finalMeta ?? {}), hardware_conflict: true };
      recordAnomaly({ agentId, eventId: event.eventId, action: event.action, type: "hardware_conflict" }).catch(() => {});
    }

    if (rateLimitExceeded) {
      recordAnomaly({ agentId, eventId: event.eventId, action: event.action, type: "rate_limit_exceeded" }).catch(() => {});
    }

    validatedEvents.push({ event, serverWithinScope, signatureValid, finalMeta });
  }

  if (validatedEvents.length === 0) {
    return res.status(400).json({ error: "No valid events to insert", code: "NO_VALID_EVENTS" });
  }

  const values: unknown[] = [];
  const placeholders: string[] = [];

  validatedEvents.forEach((ve, i) => {
    const b = i * 12;
    values.push(
      ve.event.eventId, agentId, ve.event.action, ve.event.outcome,
      ve.event.withinScope, ve.event.durationMs, ve.event.signature, ve.signatureValid,
      ve.event.error ?? null, JSON.stringify(ve.finalMeta),
      new Date(ve.event.timestamp), ve.serverWithinScope
    );
    placeholders.push(
      `($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},$${b+7},$${b+8},$${b+9},$${b+10},$${b+11},$${b+12})`
    );
  });

  try {
    await transaction(async (client) => {
      await client.query(
        `INSERT INTO events (event_id, agent_id, action, outcome, within_scope, duration_ms, signature, signature_valid, error, meta, client_ts, server_within_scope) VALUES ${placeholders.join(',')}`,
        values
      );

      await client.query("UPDATE agents SET last_seen = NOW() WHERE id = $1", [agentId]);
    });

    accepted.push(...validatedEvents.map(ve => ve.event.eventId));
  } catch (bulkErr: unknown) {
    const pgErr = bulkErr as { code?: string; detail?: string };
    if (pgErr.code === "23505") {
      const duplicateEvents: string[] = [];
      for (const ve of validatedEvents) {
        try {
          await transaction(async (client) => {
            await client.query(
              `INSERT INTO events (event_id, agent_id, action, outcome, within_scope, duration_ms, signature, signature_valid, error, meta, client_ts, server_within_scope) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
              [ve.event.eventId, agentId, ve.event.action, ve.event.outcome, ve.event.withinScope, ve.event.durationMs, ve.event.signature, ve.signatureValid, ve.event.error ?? null, JSON.stringify(ve.finalMeta), new Date(ve.event.timestamp), ve.serverWithinScope]
            );
            await client.query("UPDATE agents SET last_seen = NOW() WHERE id = $1", [agentId]);
          });
          accepted.push(ve.event.eventId);
        } catch {
          duplicateEvents.push(ve.event.eventId);
        }
      }
      for (const de of duplicateEvents) {
        rejected.push({ eventId: de, reason: "Duplicate event" });
        const idx = accepted.indexOf(de);
        if (idx > -1) accepted.splice(idx, 1);
      }
    } else {
      throw bulkErr;
    }
  }

  logEvent("log", "Completed batch event ingestion request", {
    apiKeyId: req.apiKeyId,
    accepted: accepted.length,
    rejected: rejected.length,
  });

  reputationQueue.push(agentId);

  return res.status(202).json({
    accepted: accepted.length,
    rejected: rejected.length,
    ...(rejected.length > 0 && { rejectedEvents: rejected }),
    summary
  });
});

eventsRouter.get("/", async (req, res) => {
  try {
    const { agentDid, limit = "50", cursor, outcome } = req.query as Record<string, string>;
    const pageLimit = Math.min(parseInt(limit, 10) || 50, 200);
    logEvent("log", "Listing events", {
      apiKeyId: req.apiKeyId,
      agentDid,
      requestedLimit: limit,
      pageLimit,
      cursor,
      outcome,
    });

    let sql = `
      SELECT e.event_id, e.action, e.outcome, e.within_scope, e.server_within_scope, e.signature_valid,
             e.duration_ms, e.client_ts, e.error, e.meta,
             a.did AS agent_did, a.name AS agent_name
      FROM events e
      JOIN agents a ON a.id = e.agent_id
      WHERE a.api_key_id = $1
    `;
    const params: unknown[] = [req.apiKeyId];
    let paramIdx = 2;

    if (agentDid) {
      sql += ` AND a.did = $${paramIdx++}`;
      params.push(agentDid);
    }

    if (outcome && ["success", "error", "anomaly"].includes(outcome)) {
      sql += ` AND e.outcome = $${paramIdx++}`;
      params.push(outcome);
    }

    if (cursor) {
      const cursorDate = new Date(cursor);
      if (isNaN(cursorDate.getTime())) {
        return res.status(400).json({ 
          error: 'Invalid cursor value', 
          code: 'INVALID_CURSOR' 
        });
      }
      sql += ` AND e.recorded_at < $${paramIdx++}`;
      params.push(cursorDate);
    }

    sql += ` ORDER BY e.recorded_at DESC LIMIT $${paramIdx}`;
    params.push(pageLimit);

    const result = await query(sql, params);
    logEvent("log", "Listed events successfully", {
      apiKeyId: req.apiKeyId,
      resultCount: result.rows.length,
      pageLimit,
    });

    const nextCursor =
      result.rows.length === pageLimit
        ? (result.rows[result.rows.length - 1] as { client_ts: string }).client_ts
        : null;

    return res.json({
      events: result.rows.map((row) => ({
        ...row,
        meta: sanitizeMeta(row.meta as Record<string, unknown> | null),
      })),
      ...(nextCursor && { nextCursor }),
    });
  } catch (err) {
    console.error('[routes/events] GET / error:', err instanceof Error ? err.message : 'Unknown error');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

// v1: classic HMAC-SHA256 with raw secret.
function verifySignatureV1(event: IncomingEvent, hmacKey: string): boolean {
  const payload = `${event.eventId}:${event.agentDid}:${event.action}:${event.outcome}:${event.timestamp}`;
  const expected = createHmac("sha256", hmacKey).update(payload).digest("hex");
  
  try {
    const eventBuf = Buffer.from(event.signature, "hex");
    const expectedBuf = Buffer.from(expected, "hex");
    return eventBuf.length === expectedBuf.length && timingSafeEqual(eventBuf, expectedBuf);
  } catch {
    return false; 
  }
}

// v2: DTS — HMAC-based One-Way Signature (Secure)
// Step 1: Server calculates partial_A = HMAC(ShareA, payload)
// Step 2: Client provides partial_B = HMAC(ShareB, payload) in event.meta
// Step 3: Final signature = HMAC(partial_A || partial_B, "dts_binding")
function verifySignatureV2(event: IncomingEvent, shareA: string): boolean {
  const payload = `${event.eventId}:${event.agentDid}:${event.action}:${event.outcome}:${event.timestamp}`;

  // Step 1: Derive partialA from ShareA (server-side only)
  const shareABuf = Buffer.from(shareA, "hex");
  const partialAKey = Buffer.from(
    hkdfSync("sha256", shareABuf, Buffer.alloc(0), "dts_partial_a_v2", 32) as ArrayBuffer,
  );
  const partial_A = createHmac("sha256", partialAKey).update(payload).digest();

  // Zero-out ShareA from memory immediately for security
  shareABuf.fill(0);

  // Step 2: Client must provide partial_B (already HMAC'd by client)
  const partial_B_hex = event.meta && typeof event.meta.partial_b === "string" ? event.meta.partial_b : null;
  if (partial_B_hex === null) {
    logEvent("warn", "DTS signature missing partial_B", { eventId: event.eventId });
    return false;
  }

  // Step 3: Final binding signature = HMAC(partial_A || partial_B, "dts_binding")
  const bindingKey = Buffer.concat([partial_A, Buffer.from(partial_B_hex, "hex")]);
  const finalSignature = createHmac("sha256", bindingKey).update("dts_binding").digest("hex");

  // Clean up
  partial_A.fill(0);
  bindingKey.fill(0);

  try {
    const eventBuf = Buffer.from(event.signature, "hex");
    const expectedBuf = Buffer.from(finalSignature, "hex");
    return eventBuf.length === expectedBuf.length && timingSafeEqual(eventBuf, expectedBuf);
  } catch {
    return false;
  }
}

function validateEvent(e: Partial<IncomingEvent>): string | null {
  if (!e.eventId || typeof e.eventId !== "string") return "eventId is required";
  if (!e.agentDid || !e.agentDid.startsWith("did:agentrust:")) return "agentDid must be a valid DID";
  if (!e.action || typeof e.action !== "string") return "action is required";
  if (!["success", "error", "anomaly"].includes(e.outcome ?? "")) return "outcome must be success | error | anomaly";
  if (typeof e.withinScope !== "boolean") return "withinScope must be boolean";
  if (typeof e.durationMs !== "number" || e.durationMs < 0) return "durationMs must be a non-negative number";
  if (!e.timestamp || isNaN(Date.parse(e.timestamp))) return "timestamp must be a valid ISO 8601 date";
  if (!e.signature || typeof e.signature !== "string") return "signature is required";
  return null;
}

async function ingestEvent(event: IncomingEvent, apiKeyId: string): Promise<{
  serverWithinScope: boolean;
  signatureValid: boolean;
  scope: string[];
  rateLimitInfo: ReturnType<typeof getRateLimitInfo>;
}> {
  logEvent("log", "Looking up agent for single event ingestion", {
    apiKeyId,
    eventId: event.eventId,
    agentDid: event.agentDid,
  });

  const agent = await query<{ id: string; scope: string[]; hmac_key: string | null; meta: Record<string, unknown> | null; signing_version: number }>(
    `SELECT id, scope, hmac_key, meta, signing_version FROM agents WHERE did = $1 AND api_key_id = $2`,
    [event.agentDid, apiKeyId],
  );

  if (!agent.rows[0]) {
    logEvent("warn", "Agent lookup failed for single event ingestion", {
      apiKeyId,
      eventId: event.eventId,
      agentDid: event.agentDid,
    });
    throw new Error("AGENT_NOT_FOUND");
  }

  const { id: agentId, scope, hmac_key: rawHmacKey, meta: agentMeta, signing_version: signingVersion } = agent.rows[0]!;
  const decryptedHmacKey = rawHmacKey ? decryptSecret(rawHmacKey) : null;
  const serverWithinScope = scope.includes(event.action);
  const storedShareC = typeof agentMeta?.dts_share_c === "string" ? agentMeta.dts_share_c : null;
  const eventFp = event.meta && typeof event.meta.hardwareFingerprint === "string" ? event.meta.hardwareFingerprint : null;
  
  let hardwareConflict = false;
  if (storedShareC && eventFp) {
    const derivedShareC = Buffer.from(
      hkdfSync(
        "sha256",
        Buffer.from(eventFp, "hex"),
        Buffer.alloc(0),
        "dts_share_c_v1",
        32
      ) as ArrayBuffer,
    );

    // Timing-safe comparison to prevent timing attacks
    const storedBuf = Buffer.from(storedShareC, "hex");
    if (derivedShareC.length !== storedBuf.length) {
      hardwareConflict = true;
    } else if (!timingSafeEqual(derivedShareC, storedBuf)) {
      hardwareConflict = true;
    }

    // Zero-out for security
    derivedShareC.fill(0);
    storedBuf.fill(0);
  }
  
  if (event.withinScope && !serverWithinScope) {
    logEvent("warn", "Scope conflict: agent reported withinScope=true but action is not in declared scope", {
      apiKeyId,
      eventId: event.eventId,
      agentDid: event.agentDid,
      action: event.action,
    });
  }
  const signatureValid = determineSignatureValidity(event, decryptedHmacKey, signingVersion, {
    apiKeyId,
    eventId: event.eventId,
    agentDid: event.agentDid,
    action: event.action,
  });
  logEvent("log", "Resolved agent for single event ingestion", {
    apiKeyId,
    eventId: event.eventId,
    agentDid: event.agentDid,
    agentId,
  });

  const rateLimitExceeded = checkRateLimit(agentId);
  if (rateLimitExceeded) {
    logEvent("warn", "Rate limit exceeded: event accepted but flagged", {
      apiKeyId,
      eventId: event.eventId,
      agentId,
    });
  }
  let finalMeta: Record<string, unknown> | null = rateLimitExceeded
    ? { ...event.meta, rate_limit_exceeded: true }
    : (event.meta ?? null);

  if (hardwareConflict) {
    finalMeta = { ...(finalMeta ?? {}), hardware_conflict: true };
    recordAnomaly({ agentId, eventId: event.eventId, action: event.action, type: "hardware_conflict" }).catch(() => {});
  }

  if (rateLimitExceeded) {
     // REGISTRO DE ANOMALÍA 6
     recordAnomaly({ agentId, eventId: event.eventId, action: event.action, type: "rate_limit_exceeded" }).catch(() => {});
  }
  // --- FIN DE DETECCIÓN DE ANOMALÍAS ---

  try {
    await query(
      `INSERT INTO events
         (event_id, agent_id, action, outcome, within_scope, duration_ms, signature, signature_valid, error, meta, client_ts, server_within_scope)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        event.eventId, agentId, event.action, event.outcome,
        event.withinScope, event.durationMs, event.signature, signatureValid,
        event.error ?? null, finalMeta,
        new Date(event.timestamp), serverWithinScope,
      ],
    );
  } catch (insertErr: unknown) {
    if ((insertErr as { code?: string }).code === "23505") {
      logEvent("warn", "Detected duplicate single event during insert", {
        apiKeyId,
        eventId: event.eventId,
        agentId,
      });
      throw new Error("DUPLICATE_EVENT");
    }
    throw insertErr;
  }

  logEvent("log", "Inserted single event successfully", {
    apiKeyId,
    eventId: event.eventId,
    agentId,
  });

  query("UPDATE agents SET last_seen = NOW() WHERE id = $1", [agentId]).catch((err: unknown) => {
    logEvent("warn", "Failed to update agent last_seen after single event ingestion", {
      apiKeyId,
      eventId: event.eventId,
      agentId,
      error: err instanceof Error ? err.message : String(err),
    });
  });

  reputationQueue.push(agentId);
  logEvent("log", "Queued reputation recalculation after single event ingestion", {
    apiKeyId,
    eventId: event.eventId,
    agentId,
  });

  return {
    serverWithinScope,
    signatureValid,
    scope: scope,
    rateLimitInfo: getRateLimitInfo(agentId),
  };
}