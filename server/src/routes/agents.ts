import { Router } from "express";
import { randomUUID, randomBytes, hkdfSync } from "crypto";
import * as sss from "shamirs-secret-sharing";
import bcrypt from "bcrypt";
import { query } from "../db/pool.js";
import { requireApiKey } from "../middleware/auth.js";
import { encryptSecret } from "../utils/crypto.js";
import { checkAgentLimit } from "../middleware/plans.js";
import { PLANS, type Plan } from "../config/plans.js";

export const agentsRouter = Router();

agentsRouter.use(requireApiKey);

agentsRouter.post("/", checkAgentLimit, async (req, res) => {
  const { name, scope, meta, hardwareFingerprint } = req.body as {
    name?: string;
    scope?: string[];
    meta?: Record<string, unknown>;
    hardwareFingerprint?: string;
  };

  if (!name || typeof name !== "string" || name.trim().length === 0) {
    return res.status(400).json({ error: "name is required", code: "INVALID_NAME" });
  }

  if (name.trim().length > 100) {
    return res.status(400).json({ error: "Field too long: name", code: "VALIDATION_ERROR" });
  }

  if (!Array.isArray(scope) || scope.length === 0) {
    return res.status(400).json({ error: "scope must be a non-empty array", code: "INVALID_SCOPE" });
  }

  if (scope.length > 20) {
    return res.status(400).json({ error: "Field too long: scope", code: "VALIDATION_ERROR" });
  }

  if (scope.some((s) => typeof s !== "string" || s.length > 50 || !/^[a-z]+:[a-z_]+$/.test(s))) {
    return res.status(400).json({
      error: "Each scope action must follow the pattern verb:resource (e.g. send:email)",
      code: "INVALID_SCOPE_FORMAT",
    });
  }

  if (hardwareFingerprint && !/^[0-9a-fA-F]{64}$/.test(hardwareFingerprint)) {
    return res.status(400).json({
      error: "hardwareFingerprint must be a 32-byte hex string",
      code: "INVALID_HARDWARE_FINGERPRINT",
    });
  }

  const did = `did:agentrust:${randomUUID()}`;
  const publicKey = [...scope].sort().join("|");

  // Merge hardwareFingerprint into meta if provided. Stored server-side only.
  // Derive ShareC from hardware fingerprint for DTS (hardware-bound secret).
  let shareCKey: string | null = null;
  if (hardwareFingerprint) {
    shareCKey = Buffer.from(
      hkdfSync(
        "sha256",
        Buffer.from(hardwareFingerprint, "hex"),
        Buffer.alloc(0),
        "dts_share_c_v1",
        32
      ) as ArrayBuffer
    ).toString("hex");
  }
  const storedMeta = hardwareFingerprint
    ? { ...meta, hardwareFingerprint, dts_share_c: shareCKey }
    : (meta ?? null);

  let hmacKey: string;
  let signingVersion: number;
  let secretHash: string;
  let responseCredentials: Record<string, string>;

  if (hardwareFingerprint) {
    // DTS mode
    const secretBuf = randomBytes(32);
    const shares = sss.split(secretBuf, { shares: 3, threshold: 2 });
    const shareA = Buffer.from(shares[0]!);
    const shareB = Buffer.from(shares[1]!);

// DTS CRYPTOGRAPHIC FLOW:
// ShareA → derives partialAKey via HKDF → stored encrypted in hmac_key
// ShareB → returned to client as fragmentB
// ShareC → derived from hardwareFingerprint via HKDF → stored in meta.dts_share_c
// All three shares required for valid signature verification
const partialAKey = Buffer.from(
  hkdfSync("sha256", shareA, Buffer.alloc(0), "dts_partial_a_v2", 32) as ArrayBuffer,
);

hmacKey = partialAKey.toString("hex"); // Database stores the derived key
    signingVersion = 2;
    secretHash = await bcrypt.hash(shareB.toString("hex"), 10);
    
    responseCredentials = {
      fragmentB: shareB.toString("hex"),
      signingVersion: "2",
    };
  } else {
    // Classic mode
    const secret = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
    hmacKey = secret;
    signingVersion = 1;
    secretHash = await bcrypt.hash(secret, 10);
    responseCredentials = { secret };
  }

  const encryptedHmacKey = encryptSecret(hmacKey, did);

  const keyResult = await query<{ user_id: string | null }>(
    'SELECT user_id FROM api_keys WHERE id = $1',
    [req.apiKeyId]
  );
  const userId = keyResult.rows[0]?.user_id ?? null;

  const result = await query<{ id: string; created_at: string }>(
    `INSERT INTO agents (did, name, scope, api_key_id, user_id, public_key, secret_hash, hmac_key, meta, signing_version)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     RETURNING id, created_at`,
    [did, name.trim(), scope, req.apiKeyId, userId, publicKey, secretHash, encryptedHmacKey, storedMeta, signingVersion],
  );

  const agent = result.rows[0]!;

  return res.status(201).json({
    agent: {
      did,
      name: name.trim(),
      scope,
      createdAt: agent.created_at,
      publicKey,
      // Nunca devolver meta al registrar por si acaso contiene fp u otros datos internos
    },
    ...responseCredentials,
  });
});

agentsRouter.get("/", async (req, res) => {
  try {
    const { name } = req.query as { name?: string };

    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    // Safe parameterized query construction
    const params: unknown[] = [userId, req.apiKeyId];
    let sql = `
      SELECT
        a.did, a.name, a.scope, a.created_at, a.last_seen,
        COALESCE(r.total_events, 0)  AS total_events,
        COALESCE(r.anomaly_count, 0) AS anomaly_count,
        r.success_rate, r.final_score, r.trust_level
      FROM agents a
      LEFT JOIN reputation_snapshots r ON r.agent_id = a.id
      WHERE (
        (a.user_id = $1 AND $1 IS NOT NULL)
        OR
        (a.api_key_id = $2 AND $1 IS NULL)
      )
    `;

    if (name && typeof name === "string" && name.trim().length > 0) {
      sql += ` AND a.name ILIKE $${params.length + 1}`;
      params.push(`%${name.trim()}%`);
    }

    sql += ` ORDER BY a.created_at DESC`;

    const result = await query<{
      did: string;
      name: string;
      scope: string[];
      created_at: string;
      last_seen: string | null;
      total_events: number;
      anomaly_count: number;
      success_rate: string | null;
      final_score: number | null;
      trust_level: string | null;
    }>(sql, params);

    const maskDid = (did: string) => {
      const prefix = did.slice(0, 10);
      const suffix = did.slice(-4);
      return `${prefix}...${suffix}`;
    };

    const agents = result.rows.map((row) => ({
      did: row.did,
      name: row.name,
      masked_did: maskDid(row.did),
      scope_summary: Array.isArray(row.scope) && row.scope.length > 0 ? row.scope[0] : "No scope",
      scope_count: Array.isArray(row.scope) ? row.scope.length : 0,
      created_at: row.created_at,
      last_seen: row.last_seen,
      total_events: row.total_events,
      anomaly_count: row.anomaly_count,
      success_rate: row.success_rate,
      trustScore: row.final_score,
      trustLevel: row.trust_level,
    }));

    const planResult = await query<{ plan: string }>(
      `SELECT u.plan FROM users u
       JOIN api_keys ak ON ak.owner_email = u.email
       WHERE ak.id = $1`,
      [req.apiKeyId]
    );

    const plan = (planResult.rows[0]?.plan ?? 'free') as Plan;

    return res.json({
      agents,
      plan,
      plan_config: PLANS[plan]
    });
  } catch (err) {
    console.error('[routes/agents] GET / error:', err instanceof Error ? err.message : 'Unknown error');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

agentsRouter.post("/bulk-delete", async (req, res) => {
  const { dids } = req.body as { dids?: string[] };

  if (!Array.isArray(dids) || dids.length === 0) {
    return res.status(400).json({
      error: "dids array required",
      code: "INVALID_INPUT"
    });
  }

  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const agentResult = await query<{ id: string }>(
      `SELECT id FROM agents
       WHERE did = ANY($1::text[])
       AND (user_id = $2 OR api_key_id = $3)`,
      [dids, userId, req.apiKeyId]
    );

    const agentIds = agentResult.rows.map(r => r.id);

    if (agentIds.length === 0) {
      return res.status(404).json({
        error: "No agents found",
        code: "NOT_FOUND"
      });
    }

    await query('DELETE FROM anomalies_archive WHERE agent_id = ANY($1::uuid[])', [agentIds]);
    await query('DELETE FROM anomalies WHERE agent_id = ANY($1::uuid[])', [agentIds]);
    await query('DELETE FROM reputation_snapshots WHERE agent_id = ANY($1::uuid[])', [agentIds]);
    await query('DELETE FROM events WHERE agent_id = ANY($1::uuid[])', [agentIds]);
    await query('DELETE FROM agents WHERE id = ANY($1::uuid[])', [agentIds]);

    return res.json({
      deleted: agentIds.length,
      message: `${agentIds.length} agents deleted`
    });
  } catch (err) {
    console.error('[agents] bulk-delete error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

agentsRouter.delete("/:did", async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const agentResult = await query<{ id: string }>(
      `SELECT id FROM agents
       WHERE did = $1 AND (
         (user_id = $2 AND $2 IS NOT NULL)
         OR api_key_id = $3
       )`,
      [req.params.did, userId, req.apiKeyId]
    );

    if (!agentResult.rows[0]) {
      return res.status(404).json({ error: 'Agent not found', code: 'NOT_FOUND' });
    }

    const agentId = agentResult.rows[0].id;

    await query('DELETE FROM gate_requests WHERE agent_id = $1', [agentId]);
    await query('DELETE FROM gate_rules WHERE agent_id = $1', [agentId]);
    await query('DELETE FROM anomalies_archive WHERE agent_id = $1', [agentId]);
    await query('DELETE FROM anomalies WHERE agent_id = $1', [agentId]);
    await query('DELETE FROM reputation_snapshots WHERE agent_id = $1', [agentId]);
    await query('DELETE FROM events WHERE agent_id = $1', [agentId]);
    await query('DELETE FROM agents WHERE id = $1', [agentId]);

    return res.status(204).send();
  } catch (err) {
    console.error('[agents] DELETE /:did error:', err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

agentsRouter.get("/:did/secret", async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const result = await query<{
      did: string;
      name: string;
      hmac_key: string | null;
      signing_version: number;
    }>(
      `SELECT did, name, hmac_key, signing_version
       FROM agents
       WHERE did = $1 AND (
         (user_id = $2 AND $2 IS NOT NULL)
         OR api_key_id = $3
       )`,
      [req.params.did, userId, req.apiKeyId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "Agent not found",
        code: "NOT_FOUND"
      });
    }

    const agent = result.rows[0];

    if (!agent.hmac_key) {
      return res.status(404).json({
        error: "Secret not available for this agent",
        code: "NO_SECRET"
      });
    }

    const { decryptSecret } = await import('../utils/crypto.js');
    const secret = decryptSecret(agent.hmac_key, agent.did);

    return res.json({
      did: agent.did,
      name: agent.name,
      secret,
      signing_version: agent.signing_version
    });
  } catch (err) {
    console.error('[agents] GET /:did/secret error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

agentsRouter.get("/:did/patterns", async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const agentResult = await query<{ id: string }>(
      `SELECT id FROM agents
       WHERE did = $1 AND (
         (user_id = $2 AND $2 IS NOT NULL)
         OR api_key_id = $3
       )`,
      [req.params.did, userId, req.apiKeyId]
    );

    if (!agentResult.rows[0]) {
      return res.status(404).json({ error: 'Agent not found', code: 'NOT_FOUND' });
    }

    const agentId = agentResult.rows[0].id;

    const { analyzeAgentBehavior } = await import('../services/pattern-detector.js');
    await analyzeAgentBehavior(agentId);

    const patterns = await query(
      `SELECT id, pattern_type, action, description,
              occurrences, severity, metadata,
              first_seen, last_seen, created_at
       FROM behavior_patterns
       WHERE agent_id = $1
         AND resolved_at IS NULL
       ORDER BY
         CASE severity
           WHEN 'CRITICAL' THEN 1
           WHEN 'HIGH'     THEN 2
           WHEN 'MEDIUM'   THEN 3
           WHEN 'LOW'      THEN 4
         END,
         occurrences DESC`,
      [agentId]
    );

    return res.json({
      agent_did: req.params.did,
      patterns: patterns.rows,
      analyzed_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[agents] GET /:did/patterns error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});

agentsRouter.get("/:did", async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const result = await query<{
      did: string;
      name: string;
      scope: string[];
      created_at: string;
      last_seen: string | null;
      meta: Record<string, unknown> | null;
      total_events: number;
      success_count: number;
      error_count: number;
      anomaly_count: number;
      success_rate: string | null;
      top_actions: Array<{ action: string; count: number }> | null;
      final_score: number | null;
      trust_level: string | null;
    }>(
      `SELECT
         a.did, a.name, a.scope, a.created_at, a.last_seen, a.meta,
         COALESCE(r.total_events, 0)   AS total_events,
         COALESCE(r.success_count, 0)  AS success_count,
         COALESCE(r.error_count, 0)    AS error_count,
         COALESCE(r.anomaly_count, 0)  AS anomaly_count,
         r.success_rate, r.top_actions,
         r.final_score, r.trust_level
       FROM agents a
       LEFT JOIN reputation_snapshots r ON r.agent_id = a.id
       WHERE a.did = $1 AND (
         (a.user_id = $3 AND $3 IS NOT NULL)
         OR
         (a.api_key_id = $2 AND $3 IS NULL)
       )`,
      [req.params.did, req.apiKeyId, userId],
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Invalid request", code: "NOT_FOUND" });
    }

    const row = result.rows[0]!;

    const safeMeta: Record<string, unknown> = {};
    const ALLOWED_META_KEYS = ["simulated", "version", "environment", "region"];

    if (row.meta && typeof row.meta === "object") {
      for (const key of Object.keys(row.meta)) {
        if (ALLOWED_META_KEYS.includes(key)) {
          safeMeta[key] = row.meta[key];
        }
      }
    }

    const responseAgent = {
      did: row.did,
      name: row.name,
      scope: row.scope,
      created_at: row.created_at,
      last_seen: row.last_seen,
      meta: Object.keys(safeMeta).length > 0 ? safeMeta : null,
      total_events: row.total_events,
      success_count: row.success_count,
      error_count: row.error_count,
      anomaly_count: row.anomaly_count,
      success_rate: row.success_rate,
      top_actions: row.top_actions,
      trustScore: row.final_score,
      trustLevel: row.trust_level,
    };

    return res.json({ agent: responseAgent });
  } catch (err) {
    console.error('[routes/agents] GET /:did error:', err instanceof Error ? err.message : 'Unknown error');
    return res.status(500).json({ error: 'Service unavailable', code: 'INTERNAL_ERROR' });
  }
});
