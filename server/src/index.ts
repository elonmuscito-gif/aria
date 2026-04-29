// 1. IMPORTS
import { randomUUID, createHash } from "crypto";
import { fileURLToPath } from "url";
import path from "path";
import "dotenv/config";
import { encryptSecret } from "./utils/crypto.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import express from "express";
import helmet from "helmet";
import cors from "cors";
import bcrypt from "bcrypt";
import { agentsRouter } from "./routes/agents.js";
import { eventsRouter } from "./routes/events.js";
import { authRouter } from "./routes/auth.js";
import { webhooksRouter } from "./routes/webhooks.js";
import { requireApiKey, invalidateCacheByApiKeyId } from "./middleware/auth.js";
import { checkHealth, query } from "./db/pool.js";
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { getRedisClient } from './utils/redis.js';

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

// Trust proxy for Railway (handles X-Forwarded-For header)
app.set('trust proxy', 1);

const normalizeIP = (ip: string | undefined): string => {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '');
};

const getRateLimitKey = (req: express.Request): string => {
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp && typeof cfIp === 'string') return cfIp;
  return normalizeIP(req.ip);
};

const _redis = getRedisClient();

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRateLimitKey(req),
  store: _redis ? (() => { try { return new RedisStore({ sendCommand: (...args: string[]) => (_redis as any).call(...args) }); } catch { console.warn('[rate-limit] Redis store failed, using memory'); return undefined; } })() : undefined,
  message: 'Too many requests from your network, please try again later.',
});

const setupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRateLimitKey(req),
  store: _redis ? (() => { try { return new RedisStore({ sendCommand: (...args: string[]) => (_redis as any).call(...args) }); } catch { console.warn('[rate-limit] Redis store failed, using memory'); return undefined; } })() : undefined,
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many setup attempts. Try again in 1 hour.',
      code: 'RATE_LIMITED'
    });
  }
});

const SETUP_KEY = process.env.SETUP_KEY;
if (!SETUP_KEY) {
  console.error("[startup] FATAL: SETUP_KEY env variable is required");
  process.exit(1);
}

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const BLOCKED_DOMAINS = new Set([
  'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com',
  'throwaway.email', 'yopmail.com', 'sharklasers.com', 'trashmail.com',
  'mailnull.com', 'spam4.me', 'dispostable.com', 'fakeinbox.com',
]);

app.use(helmet({ contentSecurityPolicy: false, xPoweredBy: false }));
app.disable("x-powered-by");
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(",") || ["http://localhost:3001", "http://localhost:8080"],
  credentials: true,
  methods: ["GET", "POST", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Explicit page routes registered BEFORE express.static to prevent
// static's directory-redirect from intercepting /app → /app/
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/app', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app', 'index.html'));
});

app.get('/app/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app', 'index.html'));
});

app.use(express.static(path.join(__dirname, "public")));

app.use(express.json({ limit: "1mb" }));

app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('application/json')) {
      return res.status(400).json({
        error: 'Content-Type must be application/json',
        code: 'INVALID_CONTENT_TYPE'
      });
    }
  }
  next();
});

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
app.post("/v1/setup", setupLimiter, async (req, res) => {
  const { owner_email, setup_key, name, scope } = req.body as Record<string, unknown>;
  
  if (setup_key !== SETUP_KEY) {
    res.status(403).json({ error: "Invalid setup key", code: "INVALID_SETUP_KEY" });
    return;
  }
  
  if (!owner_email || typeof owner_email !== "string") {
    res.status(400).json({ error: "owner_email is required", code: "MISSING_EMAIL" });
    return;
  }

  const normalizedEmail = owner_email.toLowerCase();
  const domain = normalizedEmail.split("@")[1] ?? "";
  if (!EMAIL_REGEX.test(normalizedEmail) || BLOCKED_DOMAINS.has(domain)) {
    res.status(400).json({ error: "Valid non-disposable owner_email is required", code: "INVALID_EMAIL" });
    return;
  }

  if (name !== undefined && (typeof name !== "string" || name.trim().length === 0 || name.trim().length > 100)) {
    res.status(400).json({ error: "name must be 1-100 characters", code: "INVALID_NAME" });
    return;
  }

  if (scope !== undefined) {
    if (!Array.isArray(scope) || scope.length === 0 || scope.length > 20 ||
        scope.some((s) => typeof s !== "string" || s.length > 50 || !/^[a-z]+:[a-z_]+$/.test(s))) {
      res.status(400).json({ error: "scope must contain valid verb:resource actions", code: "INVALID_SCOPE" });
      return;
    }
  }
  
  try {
    const existingKey = await query<{ id: string }>(
      "SELECT id FROM api_keys WHERE owner_email = $1 AND revoked_at IS NULL",
      [normalizedEmail]
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
      [randomUUID(), keyHash, keySha256, "auto-generated", normalizedEmail]
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
        [did, name, scope, apiKeyResult.rows[0].id, scope.join("|"),
         await bcrypt.hash(secret, 10), encryptSecret(secret, did), 1]
      );
      
      agentResponse = { did, name, scope, secret };
    }
    
    res.status(201).json({ 
      api_key: newKey,
      ...(agentResponse && { agent: agentResponse }),
      message: "Setup complete. Use api_key in Authorization header."
    });
  } catch(e) {
    console.error("[setup] DB error checking existing key:", e instanceof Error ? e.message : "Unknown error");
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
app.use("/v1/webhooks", apiLimiter, webhooksRouter);

// ENDPOINT 2: Create new API key
app.post("/v1/api-keys", apiLimiter, requireApiKey, async (req, res) => {
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
    console.error("[api-keys] Error:", e instanceof Error ? e.message : "Unknown error");
    res.status(500).json({ error: "Failed to create API key", code: "CREATE_KEY_ERROR" });
  }
});

// ENDPOINT 3: Rotate API key
app.post("/v1/api-keys/rotate", apiLimiter, requireApiKey, async (req, res) => {
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

    // Immediately invalidate the old key from cache so it stops working
    invalidateCacheByApiKeyId(req.apiKeyId);

    res.status(201).json({ 
      new_api_key: newKey, 
      message: "Old key revoked" 
    });
  } catch (e) {
    console.error("[api-keys] Rotate error:", e instanceof Error ? e.message : "Unknown error");
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

app.use((err: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err.type === 'entity.parse.failed' ||
      (err instanceof SyntaxError && 'body' in err)) {
    return res.status(400).json({
      error: 'Invalid request body',
      code: 'INVALID_JSON'
    });
  }
  next(err);
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("[server] Unhandled error:", err.message);

  if (err.message === "request entity too large") {
    res.status(413).json({ error: "Payload too large", code: "PAYLOAD_TOO_LARGE" });
    return;
  }

  res.status(500).json({ error: "Internal server error", code: "INTERNAL_ERROR", details: err.message });
});

// 6. ARRANQUE DEL SERVIDOR (Railway compatible)
const LISTEN_PORT = parseInt(process.env.INTERNAL_PORT || "3000", 10);
const LISTEN_HOST = process.env.INTERNAL_HOST || '127.0.0.1';
(async () => {
  app.listen(LISTEN_PORT, LISTEN_HOST, () => {
    console.log(`ARIA Internal API running on ${LISTEN_HOST}:${LISTEN_PORT}`);
  });
})();

export { app };
