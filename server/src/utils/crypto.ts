import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

const keyHex = process.env.ENCRYPTION_KEY;
if (!keyHex) {
  throw new Error('[crypto] ENCRYPTION_KEY is not set');
}
if (keyHex.length !== 64) {
  throw new Error('[crypto] ENCRYPTION_KEY must be 32 bytes (64 hex chars)');
}
if (!/^[0-9a-fA-F]+$/.test(keyHex)) {
  throw new Error('[crypto] ENCRYPTION_KEY must be valid hex');
}
const KEY = Buffer.from(keyHex, 'hex');

export function encryptSecret(plaintext: string, aad?: string): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', KEY, iv);
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return `v1:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptSecret(encrypted: string, aad?: string): string {
  try {
    const parts = encrypted.split(':');

    let ivHex: string, authTagHex: string, encryptedHex: string;

    if (parts[0] === 'v1') {
      [, ivHex, authTagHex, encryptedHex] = parts as [string, string, string, string];
    } else {
      // Legacy format without version prefix
      [ivHex, authTagHex, encryptedHex] = parts as [string, string, string];
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encryptedBuffer = Buffer.from(encryptedHex, 'hex');
    const decipher = createDecipheriv('aes-256-gcm', KEY, iv);
    decipher.setAuthTag(authTag);
    if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
    return Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final(),
    ]).toString('utf8');
  } catch (err) {
    throw new Error(`[crypto] Decryption failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
  }
}
