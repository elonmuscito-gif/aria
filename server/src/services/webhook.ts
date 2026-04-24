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

export async function triggerWebhooks(
  userId: string,
  eventType: string,
  payload: WebhookPayload
): Promise<void> {
  try {
    const result = await query<{ id: string; url: string; secret: string }>(
      `SELECT id, url, secret FROM webhooks
       WHERE user_id = $1
         AND active = true
         AND $2 = ANY(events)`,
      [userId, eventType]
    );

    for (const webhook of result.rows) {
      await deliverWebhook(webhook, payload);
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

  try {
    const response = await fetch(webhook.url, {
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

    await query(
      `UPDATE webhooks
       SET last_triggered_at = NOW(),
           failure_count = CASE
             WHEN $2 THEN failure_count
             ELSE failure_count + 1
           END
       WHERE id = $1`,
      [webhook.id, response.ok]
    );

    console.log(`[webhook] Delivered to ${webhook.url} — status ${response.status}`);
  } catch (err) {
    console.error(`[webhook] Failed to deliver to ${webhook.url}:`,
      err instanceof Error ? err.message : 'Unknown error');

    await query(
      `UPDATE webhooks
       SET failure_count = failure_count + 1,
           active = CASE WHEN failure_count >= 9 THEN false ELSE active END
       WHERE id = $1`,
      [webhook.id]
    );
  }
}
