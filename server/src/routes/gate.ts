import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { query } from '../db/pool.js';
import { requireApiKey } from '../middleware/auth.js';
import { sendGateRequestEmail } from '../services/email.js';
import { getRedisClient } from '../utils/redis.js';

export const gateRouter = Router();

const APPROVAL_TIMEOUT_MINUTES = 5;

const _gateRedis = getRedisClient();

const gateRequestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp && typeof cfIp === 'string') return cfIp;
    return req.ip?.replace(/^::ffff:/, '') ?? 'unknown';
  },
  store: _gateRedis ? (() => {
    try {
      return new RedisStore({
        sendCommand: (...args: string[]) => (_gateRedis as any).call(...args)
      });
    } catch { return undefined; }
  })() : undefined,
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many gate requests. Max 10 per minute.',
      code: 'RATE_LIMITED'
    });
  }
});

// ── GET /v1/gate/approve/:id — Email link handler (no auth required) ──────
gateRouter.get('/approve/:id', async (req, res) => {
  const { id } = req.params;
  return res.send(`<!DOCTYPE html>
<html>
<head>
  <title>ARIA Gate — Approve Action</title>
  <meta charset="UTF-8">
  <style>
    body{font-family:system-ui;background:#04060d;
         color:#f8f4ee;display:flex;align-items:center;
         justify-content:center;min-height:100vh;margin:0}
    .card{background:#07090f;border:1px solid rgba(255,255,255,0.1);
          border-top:3px solid #28c841;border-radius:8px;
          padding:40px;text-align:center;max-width:400px}
    h1{color:#28c841;margin-bottom:16px}
    p{color:rgba(248,244,238,0.6);margin-bottom:32px}
    .btn-approve{display:block;width:100%;padding:14px;
                 background:#28c841;color:#04060d;border:none;
                 border-radius:6px;font-size:16px;font-weight:600;
                 cursor:pointer}
    .btn-deny{display:block;width:100%;padding:14px;margin-top:12px;
              background:transparent;color:rgba(248,244,238,0.4);
              border:1px solid rgba(255,255,255,0.1);
              border-radius:6px;font-size:14px;cursor:pointer;
              text-decoration:none;box-sizing:border-box}
  </style>
</head>
<body>
  <div class="card">
    <h1>Approve Action</h1>
    <p>Your AI agent is waiting for your approval
       to execute this action.</p>
    <button class="btn-approve" onclick="resolve('approve')">
      Approve Action
    </button>
    <a href="/v1/gate/deny-page/${id}" class="btn-deny">
      Deny instead
    </a>
  </div>
  <script>
    async function resolve(action) {
      const r = await fetch('/v1/gate/' + action + '/${id}', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: '{}'
      });
      if (r.ok) {
        document.querySelector('.card').innerHTML =
          '<h1 style="color:#28c841">Action Approved</h1>' +
          '<p>Your agent can now proceed with the action.</p>' +
          '<p><a href="/app" style="color:#c9a84c">Back to dashboard</a></p>';
      } else {
        document.querySelector('.card').innerHTML =
          '<h1 style="color:#c94c4c">Error</h1>' +
          '<p>Request not found, already resolved, or expired.</p>' +
          '<p><a href="/app" style="color:#c9a84c">Back to dashboard</a></p>';
      }
    }
  </script>
</body>
</html>`);
});

// ── GET /v1/gate/deny-page/:id — Deny confirmation page (no auth required) ─
gateRouter.get('/deny-page/:id', async (req, res) => {
  const { id } = req.params;
  return res.send(`<!DOCTYPE html>
<html>
<head>
  <title>ARIA Gate — Deny Action</title>
  <meta charset="UTF-8">
  <style>
    body{font-family:system-ui;background:#04060d;
         color:#f8f4ee;display:flex;align-items:center;
         justify-content:center;min-height:100vh;margin:0}
    .card{background:#07090f;border:1px solid rgba(255,255,255,0.1);
          border-top:3px solid #c94c4c;border-radius:8px;
          padding:40px;text-align:center;max-width:400px}
    h1{color:#c94c4c;margin-bottom:16px}
    p{color:rgba(248,244,238,0.6);margin-bottom:32px}
    .btn-deny{display:block;width:100%;padding:14px;
              background:#c94c4c;color:#f8f4ee;border:none;
              border-radius:6px;font-size:16px;font-weight:600;
              cursor:pointer}
    .btn-back{display:block;width:100%;padding:14px;margin-top:12px;
              background:transparent;color:rgba(248,244,238,0.4);
              border:1px solid rgba(255,255,255,0.1);
              border-radius:6px;font-size:14px;cursor:pointer;
              text-decoration:none;box-sizing:border-box}
  </style>
</head>
<body>
  <div class="card">
    <h1>Deny Action</h1>
    <p>This will prevent your AI agent from executing
       the requested action.</p>
    <button class="btn-deny" onclick="denyAction()">
      Deny Action
    </button>
    <a href="/app" class="btn-back">Back to dashboard</a>
  </div>
  <script>
    async function denyAction() {
      const r = await fetch('/v1/gate/deny/${id}', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: '{}'
      });
      if (r.ok) {
        document.querySelector('.card').innerHTML =
          '<h1 style="color:#c94c4c">Action Denied</h1>' +
          '<p>Your agent has been blocked from executing this action.</p>' +
          '<p><a href="/app" style="color:#c9a84c">Back to dashboard</a></p>';
      } else {
        document.querySelector('.card').innerHTML =
          '<h1 style="color:#c94c4c">Error</h1>' +
          '<p>Request not found or already resolved.</p>' +
          '<p><a href="/app" style="color:#c9a84c">Back to dashboard</a></p>';
      }
    }
  </script>
</body>
</html>`);
});

// ── POST /v1/gate/approve/:id (no auth — UUID is the secret) ─────────────
gateRouter.post('/approve/:id', async (req, res) => {
  try {
    const result = await query<{ id: string; status: string }>(
      `UPDATE gate_requests
       SET status = 'approved',
           resolved_at = NOW(),
           resolved_by = 'email-link'
       WHERE id = $1
         AND status = 'pending'
         AND timeout_at > NOW()
       RETURNING id, status`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Gate request not found, already resolved, or timed out',
        code: 'NOT_FOUND'
      });
    }

    return res.json({
      requestId: result.rows[0].id,
      status: 'approved',
      message: 'Action approved'
    });
  } catch (err) {
    console.error('[gate] POST /approve error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── POST /v1/gate/deny/:id (no auth — UUID is the secret) ────────────────
gateRouter.post('/deny/:id', async (req, res) => {
  try {
    const result = await query<{ id: string; status: string }>(
      `UPDATE gate_requests
       SET status = 'denied',
           resolved_at = NOW(),
           resolved_by = 'email-link'
       WHERE id = $1
         AND status = 'pending'
       RETURNING id, status`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Gate request not found or already resolved',
        code: 'NOT_FOUND'
      });
    }

    return res.json({
      requestId: result.rows[0].id,
      status: 'denied',
      message: 'Action denied'
    });
  } catch (err) {
    console.error('[gate] POST /deny error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── POST /v1/gate/request ─────────────────────────────────────────────────
// SDK calls this when agent attempts a gated action.
// Returns { requestId, status } immediately.
gateRouter.post('/request', gateRequestLimiter, requireApiKey, async (req, res) => {
  const { agentDid, action, context } = req.body as {
    agentDid?: string;
    action?: string;
    context?: Record<string, unknown>;
  };

  if (!agentDid || !action) {
    return res.status(400).json({
      error: 'agentDid and action are required',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    // Get agent and owner info
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    const agentResult = await query<{
      id: string; name: string; did: string;
    }>(
      `SELECT id, name, did FROM agents
       WHERE did = $1 AND (
         user_id = $2 OR api_key_id = $3
       )`,
      [agentDid, userId, req.apiKeyId]
    );

    if (!agentResult.rows[0]) {
      return res.status(404).json({
        error: 'Agent not found',
        code: 'AGENT_NOT_FOUND'
      });
    }

    const agent = agentResult.rows[0];
    const timeoutAt = new Date(
      Date.now() + APPROVAL_TIMEOUT_MINUTES * 60 * 1000
    );

    // Check if action matches auto_block rules
    const blockRules = await query<{ id: string }>(
      `SELECT id FROM gate_rules
       WHERE agent_id = $1
       AND rule_type = 'auto_block'
       AND ($2 LIKE REPLACE(action_pattern, '*', '%')
            OR action_pattern = $2)`,
      [agent.id, action]
    );

    if (blockRules.rows.length > 0) {
      // Auto-block — no approval needed
      const result = await query<{ id: string }>(
        `INSERT INTO gate_requests
           (agent_id, agent_name, agent_did, action, context,
            status, timeout_at, user_id, owner_email)
         VALUES ($1,$2,$3,$4,$5,'auto_blocked',$6,$7,$8)
         RETURNING id`,
        [agent.id, agent.name, agent.did, action,
         context ?? {}, timeoutAt, userId, req.ownerEmail]
      );
      return res.status(200).json({
        requestId: result.rows[0]!.id,
        status: 'auto_blocked',
        message: 'Action automatically blocked by gate rules'
      });
    }

    // Create pending gate request
    const result = await query<{ id: string }>(
      `INSERT INTO gate_requests
         (agent_id, agent_name, agent_did, action, context,
          status, timeout_at, user_id, owner_email)
       VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8)
       RETURNING id`,
      [agent.id, agent.name, agent.did, action,
       context ?? {}, timeoutAt, userId, req.ownerEmail]
    );

    const requestId = result.rows[0]!.id;

    // Send email notification (non-blocking)
    sendGateRequestEmail(
      req.ownerEmail,
      agent.name,
      action,
      requestId,
      APPROVAL_TIMEOUT_MINUTES
    ).catch((err: unknown) => {
      console.error('[gate] Failed to send email:',
        err instanceof Error ? err.message : 'Unknown');
    });

    return res.status(201).json({
      requestId,
      status: 'pending',
      timeoutAt: timeoutAt.toISOString(),
      message: 'Approval request created. Owner has been notified.'
    });
  } catch (err) {
    console.error('[gate] POST /request error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── GET /v1/gate/request/:id ──────────────────────────────────────────────
// SDK polls this to check approval status.
gateRouter.get('/request/:id', requireApiKey, async (req, res) => {
  try {
    const result = await query<{
      id: string; status: string; timeout_at: string;
      resolved_at: string | null; action: string;
      agent_name: string;
    }>(
      `SELECT id, status, timeout_at, resolved_at,
              action, agent_name
       FROM gate_requests
       WHERE id = $1 AND owner_email = $2`,
      [req.params.id, req.ownerEmail]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Gate request not found',
        code: 'NOT_FOUND'
      });
    }

    const request = result.rows[0];

    // Auto-timeout if expired
    if (
      request.status === 'pending' &&
      new Date() > new Date(request.timeout_at)
    ) {
      await query(
        `UPDATE gate_requests
         SET status = 'timeout', resolved_at = NOW()
         WHERE id = $1`,
        [request.id]
      );
      request.status = 'timeout';
    }

    return res.json({
      requestId: request.id,
      status: request.status,
      action: request.action,
      agentName: request.agent_name,
      timeoutAt: request.timeout_at,
      resolvedAt: request.resolved_at
    });
  } catch (err) {
    console.error('[gate] GET /request/:id error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});

// ── GET /v1/gate/pending ──────────────────────────────────────────────────
// Dashboard lists pending approvals for this user.
gateRouter.get('/pending', requireApiKey, async (req, res) => {
  try {
    const keyResult = await query<{ user_id: string | null }>(
      'SELECT user_id FROM api_keys WHERE id = $1',
      [req.apiKeyId]
    );
    const userId = keyResult.rows[0]?.user_id ?? null;

    // Auto-expire timed out requests first
    await query(
      `UPDATE gate_requests
       SET status = 'timeout', resolved_at = NOW()
       WHERE status = 'pending'
         AND timeout_at < NOW()
         AND (user_id = $1 OR owner_email = $2)`,
      [userId, req.ownerEmail]
    );

    const result = await query(
      `SELECT id, agent_name, agent_did, action,
              status, requested_at, timeout_at, context
       FROM gate_requests
       WHERE status = 'pending'
         AND (user_id = $1 OR owner_email = $2)
       ORDER BY requested_at DESC
       LIMIT 20`,
      [userId, req.ownerEmail]
    );

    return res.json({ requests: result.rows });
  } catch (err) {
    console.error('[gate] GET /pending error:',
      err instanceof Error ? err.message : 'Unknown');
    return res.status(500).json({
      error: 'Service unavailable',
      code: 'INTERNAL_ERROR'
    });
  }
});
