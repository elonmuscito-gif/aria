// 1. IMPORTS
import { randomUUID, createHash } from "crypto";
import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import bcrypt from "bcrypt";
import { agentsRouter } from "./routes/agents.js";
import { eventsRouter } from "./routes/events.js";
import { authRouter } from "./routes/auth.js";
import { checkHealth, query } from "./db/pool.js";
import { requireApiKey } from "./middleware/auth.js";
import rateLimit from 'express-rate-limit';

// 2. MANEJO DE ERRORES CRÍTICOS
process.on("uncaughtException", (err) => {
  console.error("[fatal] Uncaught exception:", err.message);
  process.exit(1); 
});

process.on("unhandledRejection", (reason) => {
  console.error("[fatal] Unhandled rejection:", reason);
  process.exit(1);
});

// 3. CONFIGURACIÓN DE EXPRESS
const app = express();
const PORT = process.env.PORT ?? 3001;

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1500, 
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from your network, please try again later.',
});

const SETUP_KEY = process.env.SETUP_KEY;
if (!SETUP_KEY) {
  console.error("[startup] FATAL: SETUP_KEY env variable is required");
  process.exit(1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());

app.use(express.json({ limit: "1mb" }));

app.use((req, _res, next) => {
  if (!req.body || typeof req.body !== 'object') return next();
  
  function checkDepth(obj: unknown, depth: number): boolean {
    if (depth > 5) return false;
    if (typeof obj !== 'object' || obj === null) return true;
    return Object.values(obj).every(v => checkDepth(v, depth + 1));
  }
  
  if (!checkDepth(req.body, 0)) {
    _res.status(400).json({ 
      error: 'JSON nesting too deep', 
      code: 'JSON_TOO_DEEP' 
    });
    return;
  }
  next();
});

// 4. RUTA PÚBLICA DE SETUP (Chicken-and-Egg)
app.post("/v1/setup", async (req, res) => {
  const { owner_email, setup_key, name, scope } = req.body as Record<string, unknown>;
  
  if (setup_key !== SETUP_KEY) {
    res.status(403).json({ error: "Invalid setup key", code: "INVALID_SETUP_KEY" });
    return;
  }
  
  if (!owner_email || typeof owner_email !== "string") {
    res.status(400).json({ error: "owner_email is required", code: "MISSING_EMAIL" });
    return;
  }
  
  try {
    const existingKey = await query<{ id: string }>(
      "SELECT id FROM api_keys WHERE owner_email = $1 AND revoked_at IS NULL",
      [owner_email]
    );
    
    if (existingKey.rows[0]) {
      res.status(409).json({ error: "API key already exists for this email", code: "KEY_EXISTS" });
      return;
    }
    
    const newKey = randomUUID();
    const keySha256 = createHash("sha256").update(newKey).digest("hex");
    const keyHash = await bcrypt.hash(newKey, 10);
    
    const apiKeyResult = await query<{ id: string }>(
      "INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [randomUUID(), keyHash, keySha256, "auto-generated", owner_email]
    );
    
    if (!apiKeyResult.rows[0]) {
      throw new Error("Failed to create API key");
    }
    
    let agentResponse = null;
    if (name && scope && Array.isArray(scope)) {
      const did = `did:agentrust:${randomUUID()}`;
      const secret = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
      
      await query(
        `INSERT INTO agents (did, name, scope, api_key_id, public_key, secret_hash, hmac_key, signing_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [did, name, scope, apiKeyResult.rows[0].id, scope.join("|"), secret, secret, 1]
      );
      
      agentResponse = { did, name, scope, secret };
    }
    
    res.status(201).json({ 
      api_key: newKey,
      ...(agentResponse && { agent: agentResponse }),
      message: "Setup complete. Use api_key in Authorization header."
    });
  } catch(e) {
    console.error("[setup] DB error checking existing key:", e);
    return res.status(503).json({ 
      error: "Service temporarily unavailable", 
      code: "DB_ERROR" 
    });
  }
});

// 5. RUTAS PROTEGIDAS
app.use("/v1/agents", apiLimiter, agentsRouter);
app.use("/v1/events", apiLimiter, eventsRouter);
app.use("/v1/auth", authRouter);

// ENDPOINT 2: Create new API key
app.post("/v1/api-keys", requireApiKey, async (req, res) => {
  const { label } = req.body as { label?: string };
  
  if (!label || typeof label !== "string" || label.trim().length === 0) {
    return res.status(400).json({ error: "label is required", code: "MISSING_LABEL" });
  }

  try {
    const newKey = randomUUID();
    const keySha256 = createHash("sha256").update(newKey).digest("hex");
    const keyHash = await bcrypt.hash(newKey, 10);
    
    const result = await query<{ id: string }>(
      "INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [randomUUID(), keyHash, keySha256, label.trim(), req.ownerEmail]
    );

    res.status(201).json({ 
      api_key: newKey, 
      label: label.trim(), 
      created_at: new Date().toISOString() 
    });
  } catch (e) {
    console.error("[api-keys] Error:", e);
    res.status(500).json({ error: "Failed to create API key", code: "CREATE_KEY_ERROR" });
  }
});

// ENDPOINT 3: Rotate API key
app.post("/v1/api-keys/rotate", requireApiKey, async (req, res) => {
  const { label } = req.body as { label?: string };
  const newLabel = label?.trim() || "rotated-key";

  try {
    const newKey = randomUUID();
    const keySha256 = createHash("sha256").update(newKey).digest("hex");
    const keyHash = await bcrypt.hash(newKey, 10);
    
    // Insert new key
    await query(
      "INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email) VALUES ($1, $2, $3, $4, $5)",
      [randomUUID(), keyHash, keySha256, newLabel, req.ownerEmail]
    );

    // Revoke old key
    await query(
      "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1",
      [req.apiKeyId]
    );

    res.status(201).json({ 
      new_api_key: newKey, 
      message: "Old key revoked" 
    });
  } catch (e) {
    console.error("[api-keys] Rotate error:", e);
    res.status(500).json({ error: "Failed to rotate API key", code: "ROTATE_KEY_ERROR" });
  }
});

app.get("/health", async (_req, res) => {
  const dbOk = await checkHealth();
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? "ok" : "degraded",
    db: dbOk ? "connected" : "unavailable",
    uptime: Math.floor(process.uptime()),
    ts: new Date().toISOString(),
  });
});

app.use((_req, res) => {
  res.status(404).json({ error: "Not found", code: "NOT_FOUND" });
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("[server] Unhandled error:", err.message);
  console.error("[server] Stack:", err.stack);
  
  if (err.message === "request entity too large") {
    res.status(413).json({ error: "Payload too large", code: "PAYLOAD_TOO_LARGE" });
    return;
  }
  
  res.status(500).json({ error: "Internal server error", code: "INTERNAL_ERROR", details: err.message });
});

// 6. ARRANQUE DEL SERVIDOR
(async () => {
  app.listen(PORT, () => {
    console.log(`🧠 ARIA API running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV ?? "development"}`);
  });
})();

export { app };