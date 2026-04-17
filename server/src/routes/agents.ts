import { Router } from "express";
import { randomUUID, randomBytes, hkdfSync } from "crypto";
import * as sss from "shamirs-secret-sharing";
import bcrypt from "bcrypt";
import { query } from "../db/pool.js";
import { requireApiKey } from "../middleware/auth.js";

export const agentsRouter = Router();

agentsRouter.use(requireApiKey);

agentsRouter.post("/", async (req, res) => {
  const { name, scope, meta, hardwareFingerprint } = req.body as {
    name?: string;
    scope?: string[];
    meta?: Record<string, unknown>;
    hardwareFingerprint?: string;
  };

  if (!name || typeof name !== "string" || name.trim().length === 0) {
    return res.status(400).json({ error: "name is required", code: "INVALID_NAME" });
  }

  if (!Array.isArray(scope) || scope.length === 0) {
    return res.status(400).json({ error: "scope must be a non-empty array", code: "INVALID_SCOPE" });
  }

  if (scope.some((s) => typeof s !== "string" || !/^[a-z]+:[a-z_]+$/.test(s))) {
    return res.status(400).json({
      error: "Each scope action must follow the pattern verb:resource (e.g. send:email)",
      code: "INVALID_SCOPE_FORMAT",
    });
  }

  const did = `did:agentrust:${randomUUID()}`;
  const publicKey = [...scope].sort().join("|");

  // Merge hardwareFingerprint into meta if provided. Stored server-side only.
  const storedMeta = hardwareFingerprint
    ? { ...meta, hardwareFingerprint }
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

    // CORRECCIÓN DE FLUJO CRIPTOGRÁFICO:
    // 1. El servidor guarda el partialAKey derivado, NO el shareA crudo.
    // 2. Así, en events.ts solo hará HMAC normal, sin derivar de nuevo.
    const partialAKey = Buffer.from(
      hkdfSync("sha256", shareA, Buffer.alloc(0), "dts_partial_a_v2", 32) as ArrayBuffer,
    );

    hmacKey = partialAKey.toString("hex"); // <-- Ahora la DB guarda la llave derivada
    signingVersion = 2;
    secretHash = await bcrypt.hash(shareB.toString("hex"), 10);
    
    responseCredentials = {
      fragmentB: shareB.toString("hex"),
      partialAKey: hmacKey, // Ambos lados tienen la misma llave para calcular partial_A
    };
  } else {
    // Classic mode
    const secret = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
    hmacKey = secret;
    signingVersion = 1;
    secretHash = await bcrypt.hash(secret, 10);
    responseCredentials = { secret };
  }

  const result = await query<{ id: string; created_at: string }>(
    `INSERT INTO agents (did, name, scope, api_key_id, public_key, secret_hash, hmac_key, meta, signing_version)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id, created_at`,
    [did, name.trim(), scope, req.apiKeyId, publicKey, secretHash, hmacKey, storedMeta, signingVersion],
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
  const { name } = req.query as { name?: string };
  
  const nameFilter = name && typeof name === "string" && name.trim().length > 0
    ? { text: "AND a.name ILIKE $2", param: `%${name.trim()}%` }
    : { text: "", param: null };

  const result = await query<{
    did: string;
    name: string;
    scope: string[];
    created_at: string;
    last_seen: string | null;
    total_events: number;
    anomaly_count: number;
    success_rate: string | null;
  }>(
    `SELECT
       a.did, a.name, a.scope, a.created_at, a.last_seen,
       COALESCE(r.total_events, 0)  AS total_events,
       COALESCE(r.anomaly_count, 0) AS anomaly_count,
       r.success_rate
     FROM agents a
     LEFT JOIN reputation_snapshots r ON r.agent_id = a.id
     WHERE a.api_key_id = $1 ${nameFilter.text}
     ORDER BY a.created_at DESC`,
    nameFilter.param ? [req.apiKeyId, nameFilter.param] : [req.apiKeyId],
  );

  const maskDid = (did: string) => {
    const prefix = did.slice(0, 10);
    const suffix = did.slice(-4);
    return `${prefix}...${suffix}`;
  };

  const agents = result.rows.map((row) => ({
    name: row.name,
    masked_did: maskDid(row.did),
    scope_summary: Array.isArray(row.scope) && row.scope.length > 0 ? row.scope[0] : "No scope",
    scope_count: Array.isArray(row.scope) ? row.scope.length : 0,
    created_at: row.created_at,
    last_seen: row.last_seen,
    total_events: row.total_events,
    anomaly_count: row.anomaly_count,
    success_rate: row.success_rate,
  }));

  return res.json({ agents });
});

agentsRouter.get("/:did", async (req, res) => {
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
  }>(
    `SELECT
       a.did, a.name, a.scope, a.created_at, a.last_seen, a.meta,
       COALESCE(r.total_events, 0)   AS total_events,
       COALESCE(r.success_count, 0)  AS success_count,
       COALESCE(r.error_count, 0)    AS error_count,
       COALESCE(r.anomaly_count, 0)  AS anomaly_count,
       r.success_rate, r.top_actions
     FROM agents a
     LEFT JOIN reputation_snapshots r ON r.agent_id = a.id
     WHERE a.did = $1 AND a.api_key_id = $2`,
    [req.params.did, req.apiKeyId],
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "Agent not found", code: "NOT_FOUND" });
  }

  const row = result.rows[0]!;

  // SEGURIDAD DEFENSIVA: "Whitelist" en lugar de "Blacklist"
  // En lugar de intentar borrar las claves peligrosas una por una,
  // extraemos SOLO las claves que sabemos 100% que son seguras de mostrar.
  const safeMeta: Record<string, unknown> = {};
  const ALLOWED_META_KEYS = ["simulated", "version", "environment", "region"]; // Añade aquí las que consideres públicas

  if (row.meta && typeof row.meta === "object") {
    for (const key of Object.keys(row.meta)) {
      if (ALLOWED_META_KEYS.includes(key)) {
        safeMeta[key] = row.meta[key];
      }
    }
  }

  // Construimos la respuesta final inyectando el meta limpio
  const responseAgent = {
    did: row.did,
    name: row.name,
    scope: row.scope,
    created_at: row.created_at,
    last_seen: row.last_seen,
    meta: Object.keys(safeMeta).length > 0 ? safeMeta : null, // Si no hay nada seguro, devolvemos null
    total_events: row.total_events,
    success_count: row.success_count,
    error_count: row.error_count,
    anomaly_count: row.anomaly_count,
    success_rate: row.success_rate,
    top_actions: row.top_actions,
  };

  return res.json({ agent: responseAgent });
});