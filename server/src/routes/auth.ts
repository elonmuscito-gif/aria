import { Router } from "express";
import { randomUUID, createHash, randomBytes } from "crypto";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";
import { query } from "../db/pool.js";
import { requireApiKey } from "../middleware/auth.js";
import { sendConfirmationEmail, sendVerificationCode } from "../services/email.js";

export const authRouter = Router();

const normalizeIP = (ip: string | undefined): string => {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '');
};

const getRateLimitKey = (req: import("express").Request): string => {
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp && typeof cfIp === 'string') return cfIp;
  return normalizeIP(req.ip);
};

const authRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRateLimitKey(req),
  message: { error: "Too many auth requests. Try again later.", code: "RATE_LIMITED" },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRateLimitKey(req),
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many login attempts. Try again in 15 minutes.',
      code: 'RATE_LIMITED'
    });
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRateLimitKey(req),
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many registration attempts. Try again in 1 hour.',
      code: 'RATE_LIMITED'
    });
  }
});

authRouter.use(authRateLimiter);

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const BLOCKED_DOMAINS = [
  'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com',
  'throwaway.email', 'yopmail.com', 'sharklasers.com', 'trashmail.com',
  'mailnull.com', 'spam4.me', 'dispostable.com', 'fakeinbox.com',
];

function validateRegisterInput(
  req: import("express").Request,
  res: import("express").Response,
  next: import("express").NextFunction
): void {
  const { email, password, name } = req.body as { email?: string; password?: string; name?: string };

  if (!email || typeof email !== "string" || !EMAIL_REGEX.test(email)) {
    res.status(400).json({ error: "Valid email required", code: "INVALID_EMAIL" });
    return;
  }
  if (email.length > 254) {
    res.status(400).json({ error: "Field too long: email", code: "VALIDATION_ERROR" });
    return;
  }
  const domain = email.split('@')[1]?.toLowerCase() ?? '';
  if (!domain || BLOCKED_DOMAINS.includes(domain)) {
    res.status(400).json({ error: "Disposable email addresses are not allowed", code: "DISPOSABLE_EMAIL" });
    return;
  }
  if (!password || typeof password !== "string" || password.length < 8 || password.length > 128) {
    res.status(400).json({ error: "Password must be 8–128 characters", code: "INVALID_PASSWORD" });
    return;
  }
  if (name && typeof name === "string" && name.length > 100) {
    res.status(400).json({ error: "Field too long: name", code: "VALIDATION_ERROR" });
    return;
  }
  next();
}

function validateLoginInput(
  req: import("express").Request,
  res: import("express").Response,
  next: import("express").NextFunction
): void {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email || !password) {
    res.status(400).json({ error: "Email and password required", code: "MISSING_CREDENTIALS" });
    return;
  }
  if (email.length > 254 || password.length > 128) {
    res.status(400).json({ error: "Field too long", code: "VALIDATION_ERROR" });
    return;
  }
  next();
}

// ─── POST /v1/auth/register ───────────────────────────────────────────────────
// Creates user, sends confirmation email. API key is NOT issued until email confirmed.
authRouter.post("/register", registerLimiter, validateRegisterInput, async (req, res) => {
  console.log('[auth] Register endpoint hit with email:', req.body?.email);
  const { email, password, name } = req.body as { email: string; password: string; name?: string };

  try {
    const existing = await query<{ id: string; email_verified: boolean }>(
      "SELECT id, email_verified FROM users WHERE email = $1",
      [email.toLowerCase()]
    );
    if (existing.rows[0]) {
      if (existing.rows[0].email_verified) {
        return res.status(409).json({ error: "An account with this email already exists", code: "EMAIL_TAKEN" });
      }
      // Unverified — delete stale record and allow fresh registration
      await query("DELETE FROM users WHERE id = $1", [existing.rows[0].id]);
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const confirmationToken = randomBytes(32).toString('hex');
    const tokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 h

    const userResult = await query<{ id: string }>(
      `INSERT INTO users
         (email, password_hash, name, email_verified, confirmation_token, confirmation_token_expires)
       VALUES ($1, $2, $3, FALSE, $4, $5)
       RETURNING id`,
      [email.toLowerCase(), passwordHash, name?.trim() || null, confirmationToken, tokenExpires]
    );

    if (!userResult.rows[0]) {
      return res.status(500).json({ error: "Service unavailable", code: "CREATE_USER_FAILED" });
    }

    console.log('[auth] User inserted successfully, preparing email...');
    console.log('[auth] Confirmation token:', confirmationToken?.substring(0, 8) + '...');
    console.log('[auth] APP_URL:', process.env.APP_URL);

    let emailSent = false;
    try {
      console.log('[auth] Calling sendConfirmationEmail...');
      await sendConfirmationEmail(email.toLowerCase(), name?.trim() || email, confirmationToken);
      emailSent = true;
      console.log('[auth] Email sent successfully');
    } catch (err) {
      console.error('[auth] Email error details:', JSON.stringify(err));
    }

    const message = emailSent
      ? "Check your email to confirm your account"
      : "Account created. Email confirmation is temporarily unavailable — contact support to activate your account.";
    res.status(201).json({ message });
  } catch (e) {
    console.error("[auth] Register error:", e instanceof Error ? e.message : "Unknown");
    res.status(500).json({ error: "Service unavailable", code: "REGISTER_ERROR" });
  }
});

// ─── GET /v1/auth/confirm?token=xxx ──────────────────────────────────────────
// Confirms email, generates API key, saves to localStorage via redirect HTML.
authRouter.get("/confirm", async (req, res) => {
  const { token } = req.query as { token?: string };

  if (!token || typeof token !== "string" || token.length !== 64) {
    return res.status(400).send(confirmPageHtml('error', 'Invalid confirmation link.'));
  }

  try {
    const result = await query<{
      id: string; email: string; name: string | null;
      confirmation_token_expires: Date;
    }>(
      `SELECT id, email, name, confirmation_token_expires
       FROM users
       WHERE confirmation_token = $1 AND email_verified = FALSE`,
      [token]
    );

    if (!result.rows[0]) {
      return res.status(400).send(confirmPageHtml('error', 'This confirmation link is invalid or has already been used.'));
    }

    const user = result.rows[0]!;

    if (new Date() > new Date(user.confirmation_token_expires)) {
      return res.status(400).send(confirmPageHtml('error', 'This confirmation link has expired. Please register again.'));
    }

    // Mark verified, clear token
    await query(
      `UPDATE users
       SET email_verified = TRUE, confirmation_token = NULL, confirmation_token_expires = NULL
       WHERE id = $1`,
      [user.id]
    );

    return res.send(`<html><body>
      <p style="font-family:system-ui;text-align:center;margin-top:40px;color:#666">Confirmed! You can close this tab.</p>
      <script>
        if (window.opener) {
          window.opener.postMessage('aria-confirmed', '*');
          window.close();
        } else {
          window.location.href = '/app?confirmed=1';
        }
      </script>
      </body></html>`);
  } catch (e) {
    console.error("[auth] Confirm error:", e instanceof Error ? e.message : "Unknown");
    res.status(500).send(confirmPageHtml('error', 'Service unavailable. Please try again.'));
  }
});

// Tiny HTML response for the confirmation flow
function confirmPageHtml(
  type: 'success' | 'error',
  message: string,
  apiKey?: string,
  userJson?: string
): string {
  if (type === 'success' && apiKey) {
    return `<!DOCTYPE html><html><head><title>ARIA — Email Confirmed</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff}</style>
</head><body><p style="color:#666">Confirming your account…</p>
<script>
try {
  localStorage.setItem('aria_api_key', ${JSON.stringify(apiKey)});
  localStorage.setItem('aria_user', ${JSON.stringify(userJson ?? '{}')});
} catch(e){}
window.location.href = '/app?confirmed=1';
</script></body></html>`;
  }
  return `<!DOCTYPE html><html><head><title>ARIA — Confirmation Error</title>
<style>body{font-family:system-ui;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff;gap:16px}</style>
</head><body>
<p style="color:#c73535;font-size:16px">${message}</p>
<a href="/app" style="color:#0a0a0a;font-size:14px">← Back to sign in</a>
</body></html>`;
}

// ─── POST /v1/auth/login ──────────────────────────────────────────────────────
// Step 1 of 2FA: validates password, sends 6-digit code to email.
authRouter.post("/login", loginLimiter, validateLoginInput, async (req, res) => {
  const { email, password } = req.body as { email: string; password: string };

  try {
    const result = await query<{
      id: string; email: string; name: string | null;
      password_hash: string; email_verified: boolean;
    }>(
      "SELECT id, email, name, password_hash, email_verified FROM users WHERE email = $1",
      [email.toLowerCase()]
    );

    if (!result.rows[0]) {
      // Constant-time response to prevent user enumeration
      await bcrypt.hash("dummy", 10);
      return res.status(401).json({ error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
    }

    const user = result.rows[0]!;
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        error: "Please confirm your email first. Check your inbox for the confirmation link.",
        code: "EMAIL_NOT_VERIFIED"
      });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    await query(
      "UPDATE users SET verification_code = $1, verification_code_expires = $2 WHERE id = $3",
      [code, codeExpires, user.id]
    );

    await sendVerificationCode(email.toLowerCase(), code);

    res.json({ message: "Verification code sent to your email" });
  } catch (e) {
    console.error("[auth] Login error:", e instanceof Error ? e.message : "Unknown");
    res.status(500).json({ error: "Service unavailable", code: "LOGIN_ERROR" });
  }
});

// ─── POST /v1/auth/verify-code ────────────────────────────────────────────────
// Step 2 of 2FA: validates code, issues a fresh API key.
authRouter.post("/verify-code", async (req, res) => {
  const { email, code } = req.body as { email?: string; code?: string };

  if (!email || !code || typeof email !== "string" || typeof code !== "string") {
    return res.status(400).json({ error: "Email and code required", code: "MISSING_FIELDS" });
  }
  if (code.length !== 6 || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "Invalid code format", code: "INVALID_CODE" });
  }

  try {
    const result = await query<{
      id: string; email: string; name: string | null;
      verification_code: string | null; verification_code_expires: Date | null;
    }>(
      "SELECT id, email, name, verification_code, verification_code_expires FROM users WHERE email = $1",
      [email.toLowerCase()]
    );

    if (!result.rows[0]) {
      return res.status(401).json({ error: "Invalid request", code: "INVALID_CREDENTIALS" });
    }

    const user = result.rows[0]!;

    if (!user.verification_code || user.verification_code !== code) {
      return res.status(401).json({ error: "Invalid or expired code", code: "INVALID_CODE" });
    }

    if (!user.verification_code_expires || new Date() > new Date(user.verification_code_expires)) {
      return res.status(401).json({ error: "Code has expired. Please sign in again.", code: "CODE_EXPIRED" });
    }

    // Clear code + update last_login atomically
    await query(
      "UPDATE users SET verification_code = NULL, verification_code_expires = NULL, last_login = NOW() WHERE id = $1",
      [user.id]
    );

    // Return existing active key indicator, or issue a fresh one if none exists.
    // Never revoke keys on login — that would break saved keys.
    const existingKey = await query<{ id: string }>(
      "SELECT id FROM api_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
      [user.id]
    );

    let responseApiKey: string | null;
    if (existingKey.rows[0]) {
      // Active key exists — plaintext is not recoverable (stored as bcrypt hash only)
      responseApiKey = null;
    } else {
      const newKey = randomUUID();
      const keySha256 = createHash("sha256").update(newKey).digest("hex");
      const keyHash = await bcrypt.hash(newKey, 10);
      await query(
        `INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email, user_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [randomUUID(), keyHash, keySha256, "session", user.email, user.id]
      );
      responseApiKey = newKey;
    }

    res.json({
      api_key: responseApiKey,
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (e) {
    console.error("[auth] Verify-code error:", e instanceof Error ? e.message : "Unknown");
    res.status(500).json({ error: "Service unavailable", code: "VERIFY_ERROR" });
  }
});

// ─── GET /v1/auth/me (protected) ─────────────────────────────────────────────
authRouter.get("/me", requireApiKey, async (req, res) => {
  try {
    const result = await query<{
      id: string; email: string; name: string | null;
      created_at: string; last_login: string | null;
    }>(
      `SELECT id, email, name, created_at, last_login
       FROM users
       WHERE id = (SELECT user_id FROM api_keys WHERE id = $1)`,
      [req.apiKeyId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found", code: "USER_NOT_FOUND" });
    }

    res.json({ user: result.rows[0] });
  } catch (e) {
    console.error("[auth] Me error:", e instanceof Error ? e.message : "Unknown");
    res.status(500).json({ error: "Service unavailable", code: "ME_ERROR" });
  }
});
