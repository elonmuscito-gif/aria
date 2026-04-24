import { Router } from 'express';
import { randomBytes } from 'crypto';
import { query } from '../db/pool.js';
import { requireApiKey } from '../middleware/auth.js';

export const webhooksRouter = Router();

webhooksRouter.use(requireApiKey);

const VALID_EVENTS = [
  'anomaly', 'scope_violation', 'hardware_conflict',
  'rate_limit', 'trust_score_critical',
];

// POST /v1/webhooks — register webhook
webhooksRouter.post('/', async (req, res) => {
  const { url, events } = req.body as { url?: string; events?: string[] };

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url is required', code: 'MISSING_URL' });
  }

  try { new URL(url); } catch {
    return res.status(400).json({ error: 'url must be a valid URL', code: 'INVALID_URL' });
  }

  if (!url.startsWith('https://')) {
    return res.status(400).json({ error: 'url must use HTTPS', code: 'INVALID_URL' });
  }

  const eventList = Array.isArray(events) && events.length > 0
    ? events.filter(e => VALID_EVENTS.includes(e))
    : VALID_EVENTS;

  if (eventList.length === 0) {
    return res.status(400).json({ error: 'No valid event types provided', code: 'INVALID_EVENTS' });
  }

  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );

    if (!keyResult.rows[0]?.user_id) {
      return res.status(403).json({ error: 'Webhooks require a verified user account', code: 'NO_USER_ACCOUNT' });
    }

    const userId = keyResult.rows[0].user_id;
    const secret = randomBytes(32).toString('hex');

    const result = await query<{ id: string; url: string; events: string[]; created_at: string }>(
      `INSERT INTO webhooks (user_id, url, secret, events)
       VALUES ($1, $2, $3, $4)
       RETURNING id, url, events, created_at`,
      [userId, url, secret, eventList]
    );

    const webhook = result.rows[0]!;
    return res.status(201).json({
      id: webhook.id,
      url: webhook.url,
      events: webhook.events,
      secret, // shown once — never stored in plaintext after this response
      created_at: webhook.created_at,
    });
  } catch (err) {
    console.error('[webhooks] POST error:', err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'CREATE_WEBHOOK_ERROR' });
  }
});

// GET /v1/webhooks — list webhooks (secret never returned)
webhooksRouter.get('/', async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );

    if (!keyResult.rows[0]?.user_id) {
      return res.json({ webhooks: [] });
    }

    const result = await query<{
      id: string; url: string; events: string[]; active: boolean;
      created_at: string; last_triggered_at: string | null; failure_count: number;
    }>(
      `SELECT id, url, events, active, created_at, last_triggered_at, failure_count
       FROM webhooks
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [keyResult.rows[0].user_id]
    );

    return res.json({ webhooks: result.rows });
  } catch (err) {
    console.error('[webhooks] GET error:', err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'LIST_WEBHOOKS_ERROR' });
  }
});

// DELETE /v1/webhooks/:id — soft delete (verify ownership)
webhooksRouter.delete('/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );

    if (!keyResult.rows[0]?.user_id) {
      return res.status(404).json({ error: 'Not found', code: 'NOT_FOUND' });
    }

    const result = await query(
      `UPDATE webhooks SET active = false
       WHERE id = $1 AND user_id = $2`,
      [id, keyResult.rows[0].user_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Webhook not found', code: 'NOT_FOUND' });
    }

    return res.status(204).send();
  } catch (err) {
    console.error('[webhooks] DELETE error:', err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({ error: 'Service unavailable', code: 'DELETE_WEBHOOK_ERROR' });
  }
});
