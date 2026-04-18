import type { Request, Response, NextFunction } from "express";
import { createHash } from "crypto";
import bcrypt from "bcrypt";
import { query } from "../db/pool.js";

declare global {
  namespace Express {
    interface Request {
      apiKeyId: string;
      ownerEmail: string;
    }
  }
}

interface CacheEntry {
  id: string;
  email: string;
  expiresAt: number;
}

const keyCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000;
// SECURITY: Limit cache size to prevent Memory Leaks (max 10,000 keys)
const MAX_CACHE_SIZE = 10_000; 

// HELPER FUNCTION to clean expired keys from cache
function cleanExpiredCache(): void {
  const now = Date.now();
  for (const [key, entry] of keyCache.entries()) {
    if (entry.expiresAt <= now) {
      keyCache.delete(key);
    }
  }
}

export function invalidateCachedKey(rawKey: string): void {
  keyCache.delete(rawKey);
}

export function invalidateCacheByApiKeyId(apiKeyId: string): void {
  for (const [key, entry] of keyCache.entries()) {
    if (entry.id === apiKeyId) {
      keyCache.delete(key);
    }
  }
}

export async function requireApiKey(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization ?? "";
  const key = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

  if (!key) {
    res.status(401).json({ error: "Invalid request", code: "MISSING_API_KEY" });
    return;
  }

  // Compute SHA256 immediately
    const keySha256 = createHash("sha256").update(key).digest("hex");

    // FIX #5: Use keySha256 as cache key (NOT raw plaintext) to prevent memory dump attacks
    const cached = keyCache.get(keySha256);
    if (cached && cached.expiresAt > Date.now()) {
      req.apiKeyId = cached.id;
      req.ownerEmail = cached.email;
      next();
      return;
    }

  try {
    // Fast path — O(1): direct lookup by SHA-256 index.
    const fastResult = await query<{ id: string; key_hash: string; owner_email: string }>(
      "SELECT id, key_hash, owner_email FROM api_keys WHERE key_sha256 = $1 AND revoked_at IS NULL",
      [keySha256],
    );

    if (fastResult.rows[0]) {
      const row = fastResult.rows[0]!;
      if (await bcrypt.compare(key, row.key_hash)) {
        // Cache size management
        if (keyCache.size >= MAX_CACHE_SIZE) cleanExpiredCache();
        
        // Store with keySha256 as key (security improvement)
        keyCache.set(keySha256, { id: row.id, email: row.owner_email, expiresAt: Date.now() + CACHE_TTL_MS });
        req.apiKeyId = row.id;
        req.ownerEmail = row.owner_email;
        next();
        return;
      }
      // If SHA256 exists but bcrypt fails, it's an attack. Stop searching.
      res.status(401).json({ error: "Invalid request", code: "INVALID_API_KEY" });
      return;
    }

    // Slow path — O(n) BUT WITH SECURITY LIMIT.
    // Only search legacy keys if they don't have the new hash, limit to 50 to prevent DoS.
    const legacyResult = await query<{ id: string; key_hash: string; owner_email: string }>(
      "SELECT id, key_hash, owner_email FROM api_keys WHERE key_sha256 IS NULL AND revoked_at IS NULL LIMIT 50",
    );

    for (const row of legacyResult.rows) {
      if (await bcrypt.compare(key, row.key_hash)) {
        // Self-heal: write sha256 so this key hits the fast path from now on.
        query("UPDATE api_keys SET key_sha256 = $1 WHERE id = $2", [keySha256, row.id]).catch((err: unknown) => {
          console.error("[auth] Failed to self-heal key_sha256:", err instanceof Error ? err.message : "Unknown error");
        });
        
        if (keyCache.size >= MAX_CACHE_SIZE) cleanExpiredCache();
        keyCache.set(keySha256, { id: row.id, email: row.owner_email, expiresAt: Date.now() + CACHE_TTL_MS });
        req.apiKeyId = row.id;
        req.ownerEmail = row.owner_email;
        next();
        return;
      }
    }

    res.status(401).json({ error: "Invalid request", code: "INVALID_API_KEY" });
  } catch (err) {
    console.error("[auth] Error validating API key:", err instanceof Error ? err.message : "Unknown error");
    res.status(500).json({ error: "Service unavailable", code: "AUTH_ERROR" });
  }
}