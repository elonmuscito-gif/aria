import { createHmac } from 'crypto';
import { query } from '../db/pool.js';

export interface WebhookPayload {
  alert: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  agent: {
    did: string;
    name: string;
    trustScore?: number;
    trustLevel?: string;
  };
  reason: string;
  action?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

const RETRY_DELAYS = [30_000, 120_000, 600_000]; // 30s, 2min, 10min

export async function triggerWebhooks(
  userId: string,
  eventType: string,
  payload: WebhookPayload
): Promise<void> {
  try {
    const result = await query<{ id: string; url: string; secret: string; failure_count: number }>(
      `SELECT id, url, secret, failure_count FROM webhooks
       WHERE user_id = $1
         AND active = true
         AND $2 = ANY(events)`,
      [userId, eventType]
    );

    for (const webhook of result.rows) {
      await deliverWithRetry(webhook, payload);
    }
  } catch (err) {
    console.error('[webhook] Failed to trigger webhooks:',
      err instanceof Error ? err.message : 'Unknown error');
  }
}

async function deliverWebhook(
  webhook: { id: string; url: string; secret: string },
  payload: WebhookPayload
): Promise<void> {
  const body = JSON.stringify(payload);
  const timestamp = Date.now().toString();
  const signature = createHmac('sha256', webhook.secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');

  let response: Response;
  try {
    response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ARIA-Signature': `t=${timestamp},v1=${signature}`,
        'X-ARIA-Event': payload.alert,
        'User-Agent': 'ARIA-Webhooks/1.0',
      },
      body,
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    await query(`UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = $1`, [webhook.id]);
    throw err;
  }

  if (!response.ok) {
    await query(`UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = $1`, [webhook.id]);
    throw new Error(`HTTP ${response.status}`);
  }

  await query(`UPDATE webhooks SET last_triggered_at = NOW() WHERE id = $1`, [webhook.id]);
  console.log(`[webhook] Delivered to ${webhook.url} — status ${response.status}`);
}

async function deliverWithRetry(
  webhook: { id: string; url: string; secret: string; failure_count: number },
  payload: WebhookPayload,
  attempt = 0
): Promise<void> {
  try {
    await deliverWebhook(webhook, payload);
  } catch {
    if (attempt < RETRY_DELAYS.length) {
      const delay = RETRY_DELAYS[attempt]!;
      console.warn(`[webhook] Retrying in ${delay / 1000}s (attempt ${attempt + 1})`);
      setTimeout(() => deliverWithRetry(webhook, payload, attempt + 1), delay);
    } else {
      console.error(`[webhook] Max retries reached for ${webhook.url}`);
      await query(
        `UPDATE webhooks SET active = false WHERE id = $1`,
        [webhook.id]
      );
    }
  }
}
