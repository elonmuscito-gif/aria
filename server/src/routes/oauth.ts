import { Router } from 'express';
import { randomUUID, createHash } from 'crypto';
import bcrypt from 'bcrypt';
import { generateState, generateCodeVerifier } from 'arctic';
import { query } from '../db/pool.js';
import { googleOAuth, githubOAuth, isOAuthEnabled } from '../services/oauth.js';

export const oauthRouter = Router();

// Short-lived in-memory state store — cleaned every 5 minutes
interface OAuthState {
  provider: string;
  codeVerifier?: string; // Google PKCE
  expiresAt: number;
}
const oauthStates = new Map<string, OAuthState>();

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of oauthStates.entries()) {
    if (val.expiresAt < now) oauthStates.delete(key);
  }
}, 5 * 60 * 1000);

// ─── GET /v1/auth/google ──────────────────────────────────────────────────────
oauthRouter.get('/google', (_req, res) => {
  if (!isOAuthEnabled().google) {
    return res.status(503).json({
      error: 'Google OAuth not configured',
      code: 'OAUTH_NOT_CONFIGURED'
    });
  }

  try {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const url = googleOAuth.createAuthorizationURL(state, codeVerifier, [
      'openid', 'email', 'profile'
    ]);

    oauthStates.set(state, {
      provider: 'google',
      codeVerifier,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    return res.redirect(url.toString());
  } catch (err) {
    console.error('[oauth] Google redirect error:', err);
    return res.redirect('/app?error=oauth_failed');
  }
});

// ─── GET /v1/auth/google/callback ────────────────────────────────────────────
oauthRouter.get('/google/callback', async (req, res) => {
  const { code, state, error } = req.query as {
    code?: string; state?: string; error?: string;
  };

  if (error || !code || !state) {
    return res.redirect('/app?error=oauth_denied');
  }

  const stored = oauthStates.get(state);
  if (!stored || stored.provider !== 'google') {
    return res.redirect('/app?error=oauth_invalid_state');
  }
  oauthStates.delete(state);

  try {
    const tokens = await googleOAuth.validateAuthorizationCode(
      code, stored.codeVerifier!
    );

    const userInfoRes = await fetch(
      'https://openidconnect.googleapis.com/v1/userinfo',
      { headers: { Authorization: `Bearer ${tokens.accessToken()}` } }
    );
    const userInfo = await userInfoRes.json() as {
      sub: string; email: string; name?: string; picture?: string;
    };

    const rawKey = await findOrCreateOAuthUser(
      userInfo.email,
      userInfo.name || userInfo.email.split('@')[0] || userInfo.email,
      'google',
      userInfo.sub,
      userInfo.picture
    );

    return res.redirect(`/app?oauth_key=${rawKey}`);
  } catch (err) {
    console.error('[oauth] Google callback error:', err);
    return res.redirect('/app?error=oauth_failed');
  }
});

// ─── GET /v1/auth/github ──────────────────────────────────────────────────────
oauthRouter.get('/github', (_req, res) => {
  if (!isOAuthEnabled().github) {
    return res.status(503).json({
      error: 'GitHub OAuth not configured',
      code: 'OAUTH_NOT_CONFIGURED'
    });
  }

  try {
    const state = generateState();
    const url = githubOAuth.createAuthorizationURL(state, ['user:email']);

    oauthStates.set(state, {
      provider: 'github',
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    return res.redirect(url.toString());
  } catch (err) {
    console.error('[oauth] GitHub redirect error:', err);
    return res.redirect('/app?error=oauth_failed');
  }
});

// ─── GET /v1/auth/github/callback ────────────────────────────────────────────
oauthRouter.get('/github/callback', async (req, res) => {
  const { code, state, error } = req.query as {
    code?: string; state?: string; error?: string;
  };

  if (error || !code || !state) {
    return res.redirect('/app?error=oauth_denied');
  }

  const stored = oauthStates.get(state);
  if (!stored || stored.provider !== 'github') {
    return res.redirect('/app?error=oauth_invalid_state');
  }
  oauthStates.delete(state);

  try {
    const tokens = await githubOAuth.validateAuthorizationCode(code);

    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokens.accessToken()}`,
        'User-Agent': 'ARIA/1.0'
      }
    });
    const githubUser = await userRes.json() as {
      id: number; login: string; name?: string;
      avatar_url?: string; email?: string | null;
    };

    let email = githubUser.email || null;
    if (!email) {
      const emailsRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${tokens.accessToken()}`,
          'User-Agent': 'ARIA/1.0'
        }
      });
      const emails = await emailsRes.json() as Array<{
        email: string; primary: boolean; verified: boolean;
      }>;
      email = emails.find(e => e.primary && e.verified)?.email || null;
    }

    if (!email) {
      return res.redirect('/app?error=oauth_no_email');
    }

    const rawKey = await findOrCreateOAuthUser(
      email,
      githubUser.name || githubUser.login,
      'github',
      String(githubUser.id),
      githubUser.avatar_url
    );

    return res.redirect(`/app?oauth_key=${rawKey}`);
  } catch (err) {
    console.error('[oauth] GitHub callback error:', err);
    return res.redirect('/app?error=oauth_failed');
  }
});

// ─── Shared: find or create user, return raw API key ─────────────────────────
async function findOrCreateOAuthUser(
  email: string,
  name: string,
  provider: 'google' | 'github',
  oauthId: string,
  avatarUrl?: string
): Promise<string> {
  const normalizedEmail = email.toLowerCase().trim();

  // Look up by provider+id first
  let userResult = await query<{ id: string }>(
    'SELECT id FROM users WHERE oauth_provider = $1 AND oauth_id = $2',
    [provider, oauthId]
  );

  // Fall back to email lookup — link OAuth to existing account
  if (!userResult.rows[0]) {
    userResult = await query<{ id: string }>(
      'SELECT id FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (userResult.rows[0]) {
      await query(
        `UPDATE users
         SET oauth_provider = $1, oauth_id = $2, avatar_url = $3, email_verified = true
         WHERE id = $4`,
        [provider, oauthId, avatarUrl ?? null, userResult.rows[0].id]
      );
    }
  }

  // Create new user if none found
  if (!userResult.rows[0]) {
    const newUser = await query<{ id: string }>(
      `INSERT INTO users
         (email, name, email_verified, oauth_provider, oauth_id, avatar_url, password_hash)
       VALUES ($1, $2, true, $3, $4, $5, '')
       RETURNING id`,
      [normalizedEmail, name, provider, oauthId, avatarUrl ?? null]
    );
    userResult = newUser;
  }

  const userId = userResult.rows[0]!.id;

  // Issue a new API key — same pattern as rest of codebase
  const rawKey = randomUUID();
  const keySha256 = createHash('sha256').update(rawKey).digest('hex');
  const keyHash = await bcrypt.hash(rawKey, 10);

  await query(
    `INSERT INTO api_keys (id, key_hash, key_sha256, label, owner_email, user_id)
     VALUES ($1, $2, $3, 'oauth-login', $4, $5)`,
    [randomUUID(), keyHash, keySha256, normalizedEmail, userId]
  );

  console.log(`[oauth] ${provider} login for ${normalizedEmail}`);
  return rawKey;
}
