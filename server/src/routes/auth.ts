import { Router } from "express";
import { randomUUID, createHash } from "crypto";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";
import { query } from "../db/pool.js";
import { requireApiKey } from "../middleware/auth.js";

export const authRouter = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later.", code: "RATE_LIMITED" },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later.", code: "RATE_LIMITED" },
});

const setupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later.", code: "RATE_LIMITED" },
});

function validateRegisterInput(req: import("express").Request, res: import("express").Response, next: import("express").NextFunction): void {
  const { email, password, name } = req.body as { email?: string; password?: string; name?: string };

  if (!email || typeof email !== "string" || !email.includes("@")) {
    res.status(400).json({ error: "Valid email required", code: "INVALID_EMAIL" });
    return;
  }
  if (email.length > 254) {
    res.status(400).json({ error: "Field too long: email", code: "VALIDATION_ERROR" });
    return;
  }
  if (!password || typeof password !== "string" || password.length < 8 || password.length > 128) {
    res.status(400).json({ error: "Password must be at least 8 characters", code: "INVALID_PASSWORD" });
    return;
  }
  if (name && typeof name === "string" && name.length > 100) {
    res.status(400).json({ error: "Field too long: name", code: "VALIDATION_ERROR" });
    return;
  }
  next();
}

// POST /v1/auth/register
authRouter.post("/register", validateRegisterInput, registerLimiter, async (req, res) => {
  // Validation guaranteed by validateRegisterInput middleware
  const { email, password, name } = req.body as {
    email: string;
    password: string;
    name?: string;
  };

  try {
    // Check if user exists
    const existing = await query<{ id: string }>(
      "SELECT id FROM users WHERE email = $1",
      [email.toLowerCase()]
    );

    if (existing.rows[0]) {
      return res.status(409).json({ error: "Invalid request", code: "EMAIL_EXISTS" });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const userResult = await query<{ id: string }>(
      "INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id",
      [email.toLowerCase(), passwordHash, name || null]
    );

    const userRow = userResult.rows[0];
    if (!userRow) {
      return res.status(500).json({ error: "Service unavailable", code: "CREATE_USER_FAILED" });
    }
    const userId = userRow.id;

    // Generate API key for user
    const apiKey = randomUUID();
    const keySha256 = createHash("sha256").update(apiKey).digest("hex");
    const keyHash = await bcrypt.hash(apiKey, 10);

    await query(
      "INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email, user_id) VALUES ($1, $2, $3, $4, $5, $6)",
      [randomUUID(), keyHash, keySha256, "auto-generated", email.toLowerCase(), userId]
    );

    res.status(201).json({
      user: { id: userId, email: email.toLowerCase(), name: name || null },
      api_key: apiKey,
    });
  } catch (e) {
    console.error("[auth] Register error:", e instanceof Error ? e.message : "Unknown error");
    res.status(500).json({ error: "Service unavailable", code: "REGISTER_ERROR" });
  }
});

function validateLoginInput(req: import("express").Request, res: import("express").Response, next: import("express").NextFunction): void {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password) {
    res.status(400).json({ error: "Email and password required", code: "MISSING_CREDENTIALS" });
    return;
  }
  if (email.length > 254 || password.length > 128) {
    res.status(400).json({ error: "Field too long: email", code: "VALIDATION_ERROR" });
    return;
  }
  next();
}

// POST /v1/auth/login
authRouter.post("/login", validateLoginInput, loginLimiter, async (req, res) => {
  // Validation guaranteed by validateLoginInput middleware
  const { email, password } = req.body as {
    email: string;
    password: string;
  };

  try {
    const result = await query<{ id: string; email: string; name: string | null; password_hash: string }>(
      "SELECT id, email, name, password_hash FROM users WHERE email = $1",
      [email.toLowerCase()]
    );

    if (!result.rows[0]) {
      return res.status(401).json({ error: "Invalid request", code: "INVALID_CREDENTIALS" });
    }

    const user = result.rows[0]!;

    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid request", code: "INVALID_CREDENTIALS" });
    }

    // Update last_login
    await query("UPDATE users SET last_login = NOW() WHERE id = $1", [user.id]);

    // Get API key for user
    const keyResult = await query<{ key_sha256: string }>(
      "SELECT key_sha256 FROM api_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
      [user.id]
    );

    // Find the actual API key (we need to search since we store hash)
    // For login, we return the most recent active key
    const apiKeysResult = await query<{ id: string }>(
      "SELECT id FROM api_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
      [user.id]
    );

    if (!apiKeysResult.rows[0]) {
      return res.status(500).json({ error: "Invalid request", code: "NO_API_KEY" });
    }

    // Generate a new API key for this login session
    const newApiKey = randomUUID();
    const keySha256 = createHash("sha256").update(newApiKey).digest("hex");
    const keyHash = await bcrypt.hash(newApiKey, 10);

    await query(
      "INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email, user_id) VALUES ($1, $2, $3, $4, $5, $6)",
      [randomUUID(), keyHash, keySha256, "session-key", user.email, user.id]
    );

    res.json({
      user: { id: user.id, email: user.email, name: user.name },
      api_key: newApiKey,
    });
  } catch (e) {
    console.error("[auth] Login error:", e instanceof Error ? e.message : "Unknown error");
    res.status(500).json({ error: "Service unavailable", code: "LOGIN_ERROR" });
  }
});

// GET /v1/auth/me (protected)
authRouter.get("/me", requireApiKey, async (req, res) => {
  try {
    const result = await query<{ id: string; email: string; name: string | null; created_at: string; last_login: string | null }>(
      "SELECT id, email, name, created_at, last_login FROM users WHERE id = (SELECT user_id FROM api_keys WHERE id = $1)",
      [req.apiKeyId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Invalid request", code: "USER_NOT_FOUND" });
    }

    res.json({ user: result.rows[0] });
  } catch (e) {
    console.error("[auth] Me error:", e instanceof Error ? e.message : "Unknown error");
    res.status(500).json({ error: "Service unavailable", code: "ME_ERROR" });
  }
});