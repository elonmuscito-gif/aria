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
// SEGURIDAD: Limitar el tamaño del caché para evitar Memory Leaks (máx 10,000 claves únicas)
const MAX_CACHE_SIZE = 10_000; 

// FUNCIÓN AUXILIAR para limpiar claves viejas del caché
function cleanExpiredCache(): void {
  const now = Date.now();
  for (const [key, entry] of keyCache.entries()) {
    if (entry.expiresAt <= now) {
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
    res.status(401).json({ error: "Missing API key", code: "MISSING_API_KEY" });
    return;
  }

  const cached = keyCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    req.apiKeyId = cached.id;
    req.ownerEmail = cached.email;
    next();
    return;
  }

  try {
    const keySha256 = createHash("sha256").update(key).digest("hex");

    // Fast path — O(1): direct lookup by SHA-256 index.
    const fastResult = await query<{ id: string; key_hash: string; owner_email: string }>(
      "SELECT id, key_hash, owner_email FROM api_keys WHERE key_sha256 = $1 AND revoked_at IS NULL",
      [keySha256],
    );

    if (fastResult.rows[0]) {
      const row = fastResult.rows[0]!;
      if (await bcrypt.compare(key, row.key_hash)) {
        // Manejo del tamaño del caché
        if (keyCache.size >= MAX_CACHE_SIZE) cleanExpiredCache();
        
        keyCache.set(key, { id: row.id, email: row.owner_email, expiresAt: Date.now() + CACHE_TTL_MS });
        req.apiKeyId = row.id;
        req.ownerEmail = row.owner_email;
        next();
        return;
      }
      // Si el hash SHA256 existe pero el bcrypt falla, es un ataque. No seguimos buscando.
      res.status(401).json({ error: "Invalid API key", code: "INVALID_API_KEY" });
      return;
    }

    // Slow path — O(n) PERO CON LÍMITE DE SEGURIDAD.
    // Solo buscamos en claves legacy si NO tienen el hash nuevo, y limitamos a 50 para evitar DoS.
    const legacyResult = await query<{ id: string; key_hash: string; owner_email: string }>(
      "SELECT id, key_hash, owner_email FROM api_keys WHERE key_sha256 IS NULL AND revoked_at IS NULL LIMIT 50",
    );

    for (const row of legacyResult.rows) {
      if (await bcrypt.compare(key, row.key_hash)) {
        // Self-heal: write sha256 so this key hits the fast path from now on.
        query("UPDATE api_keys SET key_sha256 = $1 WHERE id = $2", [keySha256, row.id]).catch((err: unknown) => {
          console.error("[auth] Failed to self-heal key_sha256 for key", row.id, err);
        });
        
        if (keyCache.size >= MAX_CACHE_SIZE) cleanExpiredCache();
        keyCache.set(key, { id: row.id, email: row.owner_email, expiresAt: Date.now() + CACHE_TTL_MS });
        req.apiKeyId = row.id;
        req.ownerEmail = row.owner_email;
        next();
        return;
      }
    }

    res.status(401).json({ error: "Invalid API key", code: "INVALID_API_KEY" });
  } catch (err) {
    console.error("[auth] Error validating API key:", err);
    res.status(500).json({ error: "Authentication service unavailable", code: "AUTH_ERROR" });
  }
}