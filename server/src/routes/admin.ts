import { Router, type Request, type Response, type NextFunction } from 'express';
import { query } from '../db/pool.js';
import { getRedisClient } from '../utils/redis.js';

export const adminRouter = Router();

const SETUP_KEY = process.env.SETUP_KEY;

// ── Auth middleware ───────────────────────────────────
function requireSetupKey(
  req: Request, res: Response, next: NextFunction
): void {
  const key = req.headers['x-setup-key'];
  if (!key || key !== SETUP_KEY) {
    res.status(403).json({
      error: 'Invalid setup key',
      code: 'FORBIDDEN'
    });
    return;
  }
  next();
}

adminRouter.use(requireSetupKey);

// ── Admin log helper ──────────────────────────────────
async function logAdminAction(
  action: string,
  targetType: string | null,
  targetId: string | null,
  details: Record<string, unknown>,
  ip: string
): Promise<void> {
  await query(`
    INSERT INTO admin_logs
      (action, target_type, target_id, details, ip_address)
    VALUES ($1,$2,$3,$4,$5)
  `, [action, targetType, targetId, JSON.stringify(details), ip]);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// USERS & AGENTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/users
adminRouter.get('/users', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        u.id, u.email, u.name, u.email_verified,
        u.created_at, u.last_login,
        COUNT(DISTINCT a.id) AS agent_count,
        COUNT(DISTINCT ak.id) AS key_count,
        MAX(e.recorded_at) AS last_event
      FROM users u
      LEFT JOIN api_keys ak ON ak.owner_email = u.email
        AND ak.revoked_at IS NULL
      LEFT JOIN agents a ON a.user_id = u.id
      LEFT JOIN events e ON e.agent_id = a.id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);
    return res.json({ users: result.rows });
  } catch (err) {
    console.error('[admin] GET /users error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// GET /v1/admin/users/:userId/agents
adminRouter.get('/users/:userId/agents', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        a.id, a.did, a.name, a.scope, a.created_at, a.last_seen,
        COALESCE(r.total_events, 0) AS total_events,
        COALESCE(r.final_score, 0) AS trust_score,
        r.trust_level,
        COALESCE(r.scope_violation_count, 0) AS violations
      FROM agents a
      LEFT JOIN reputation_snapshots r ON r.agent_id = a.id
      WHERE a.user_id = $1
      ORDER BY a.created_at DESC
    `, [req.params.userId]);
    return res.json({ agents: result.rows });
  } catch (err) {
    console.error('[admin] GET /users/:userId/agents error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /v1/admin/users/:userId/plan
adminRouter.post('/users/:userId/plan', async (req, res) => {
  const { plan } = req.body as { plan?: string };

  if (!['free', 'professional', 'enterprise'].includes(plan ?? '')) {
    return res.status(400).json({
      error: 'Plan must be free, professional, or enterprise'
    });
  }

  try {
    await query(`
      UPDATE users
      SET plan = $1,
          plan_started_at = NOW()
      WHERE id = $2
    `, [plan, req.params.userId]);

    await logAdminAction(
      'change_plan', 'user', req.params.userId,
      { plan }, req.ip ?? 'unknown'
    );

    return res.json({ message: `Plan updated to ${plan}` });
  } catch (err) {
    console.error('[admin] POST /users/:userId/plan error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /v1/admin/users/:userId/suspend
adminRouter.post('/users/:userId/suspend', async (req, res) => {
  try {
    await query(`
      UPDATE api_keys SET revoked_at = NOW()
      WHERE owner_email = (
        SELECT email FROM users WHERE id = $1
      ) AND revoked_at IS NULL
    `, [req.params.userId]);

    await logAdminAction(
      'suspend_user', 'user', req.params.userId,
      { reason: req.body.reason ?? 'Admin action' },
      req.ip ?? 'unknown'
    );

    return res.json({ message: 'User suspended — all keys revoked' });
  } catch (err) {
    console.error('[admin] POST /users/:userId/suspend error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// DELETE /v1/admin/agents/:agentId
adminRouter.delete('/agents/:agentId', async (req, res) => {
  try {
    await query('DELETE FROM gate_requests WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM gate_rules WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM behavior_patterns WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM witness_checks WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM temporal_proofs WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM temporal_anchors WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM zero_proofs WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM anomalies_archive WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM anomalies WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM reputation_snapshots WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM events WHERE agent_id = $1', [req.params.agentId]);
    await query('DELETE FROM agents WHERE id = $1', [req.params.agentId]);

    await logAdminAction(
      'delete_agent', 'agent', req.params.agentId,
      {}, req.ip ?? 'unknown'
    );

    return res.json({ message: 'Agent deleted' });
  } catch (err) {
    console.error('[admin] DELETE /agents/:agentId error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /v1/admin/agents/:agentId/reset-trust
adminRouter.post('/agents/:agentId/reset-trust', async (req, res) => {
  try {
    await query(`
      UPDATE reputation_snapshots
      SET final_score = 50, trust_level = 'NEUTRAL',
          last_computed_at = NOW()
      WHERE agent_id = $1
    `, [req.params.agentId]);

    await logAdminAction(
      'reset_trust', 'agent', req.params.agentId,
      {}, req.ip ?? 'unknown'
    );

    return res.json({ message: 'Trust score reset to 50' });
  } catch (err) {
    console.error('[admin] POST /agents/:agentId/reset-trust error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EVENTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/events
adminRouter.get('/events', async (req, res) => {
  try {
    const {
      limit = '50',
      outcome,
      agentId,
      violations_only
    } = req.query as Record<string, string>;

    let sql = `
      SELECT
        e.event_id, e.action, e.outcome,
        e.server_within_scope, e.signature_valid,
        e.duration_ms, e.client_ts, e.recorded_at,
        a.name AS agent_name, a.did AS agent_did,
        u.email AS owner_email
      FROM events e
      JOIN agents a ON a.id = e.agent_id
      LEFT JOIN users u ON u.id = a.user_id
      WHERE 1=1
    `;
    const params: unknown[] = [];
    let idx = 1;

    if (outcome) {
      sql += ` AND e.outcome = $${idx++}`;
      params.push(outcome);
    }
    if (agentId) {
      sql += ` AND e.agent_id = $${idx++}`;
      params.push(agentId);
    }
    if (violations_only === 'true') {
      sql += ` AND e.server_within_scope = false`;
    }

    sql += ` ORDER BY e.recorded_at DESC LIMIT $${idx}`;
    params.push(Math.min(parseInt(limit), 500));

    const result = await query(sql, params);
    return res.json({ events: result.rows });
  } catch (err) {
    console.error('[admin] GET /events error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GATE
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/gate
adminRouter.get('/gate', async (req, res) => {
  try {
    const { status = 'all' } = req.query as Record<string, string>;

    let sql = `
      SELECT
        gr.id, gr.agent_name, gr.agent_did,
        gr.action, gr.status, gr.context,
        gr.requested_at, gr.resolved_at,
        gr.resolved_by, gr.timeout_at,
        u.email AS owner_email
      FROM gate_requests gr
      LEFT JOIN users u ON u.id = gr.user_id
      WHERE 1=1
    `;
    const params: unknown[] = [];

    if (status !== 'all') {
      sql += ` AND gr.status = $1`;
      params.push(status);
    }

    sql += ` ORDER BY gr.requested_at DESC LIMIT 100`;

    const result = await query(sql, params);
    return res.json({ requests: result.rows });
  } catch (err) {
    console.error('[admin] GET /gate error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SECURITY — IPs & Keys
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/security/blocked-ips
adminRouter.get('/security/blocked-ips', async (req, res) => {
  try {
    const redis = getRedisClient();
    if (!redis) {
      return res.json({ blocked_ips: [], message: 'Redis unavailable' });
    }

    const keys = await redis.keys('membrane:blocked:*');
    const ips = keys.map(k => k.replace('membrane:blocked:', ''));

    return res.json({ blocked_ips: ips, count: ips.length });
  } catch (err) {
    console.error('[admin] GET /security/blocked-ips error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /v1/admin/security/block-ip
adminRouter.post('/security/block-ip', async (req, res) => {
  const { ip, hours = 24 } = req.body as {
    ip?: string; hours?: number
  };

  if (!ip) {
    return res.status(400).json({ error: 'ip required' });
  }

  try {
    const redis = getRedisClient();
    if (redis) {
      await redis.set(
        `membrane:blocked:${ip}`, '1',
        'EX', hours * 3600
      );
    }

    await logAdminAction(
      'block_ip', 'ip', ip,
      { hours }, req.ip ?? 'unknown'
    );

    return res.json({
      message: `IP ${ip} blocked for ${hours} hours`
    });
  } catch (err) {
    console.error('[admin] POST /security/block-ip error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /v1/admin/security/unblock-ip
adminRouter.post('/security/unblock-ip', async (req, res) => {
  const { ip } = req.body as { ip?: string };

  if (!ip) {
    return res.status(400).json({ error: 'ip required' });
  }

  try {
    const redis = getRedisClient();
    if (redis) {
      await redis.del(`membrane:blocked:${ip}`);
    }

    await logAdminAction(
      'unblock_ip', 'ip', ip,
      {}, req.ip ?? 'unknown'
    );

    return res.json({ message: `IP ${ip} unblocked` });
  } catch (err) {
    console.error('[admin] POST /security/unblock-ip error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /v1/admin/security/revoke-key
adminRouter.post('/security/revoke-key', async (req, res) => {
  const { keyId } = req.body as { keyId?: string };

  if (!keyId) {
    return res.status(400).json({ error: 'keyId required' });
  }

  try {
    await query(`
      UPDATE api_keys SET revoked_at = NOW()
      WHERE id = $1
    `, [keyId]);

    await logAdminAction(
      'revoke_key', 'api_key', keyId,
      {}, req.ip ?? 'unknown'
    );

    return res.json({ message: 'API key revoked' });
  } catch (err) {
    console.error('[admin] POST /security/revoke-key error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// GET /v1/admin/security/api-keys
adminRouter.get('/security/api-keys', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        ak.id, ak.label, ak.owner_email,
        ak.created_at, ak.revoked_at,
        u.id AS user_id
      FROM api_keys ak
      LEFT JOIN users u ON u.email = ak.owner_email
      ORDER BY ak.created_at DESC
      LIMIT 100
    `);
    return res.json({ keys: result.rows });
  } catch (err) {
    console.error('[admin] GET /security/api-keys error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SYSTEM HEALTH
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/health
adminRouter.get('/health', async (req, res) => {
  try {
    const redis = getRedisClient();
    let redisOk = false;
    try {
      if (redis) {
        await redis.ping();
        redisOk = true;
      }
    } catch {}

    const stats = await query(`
      SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM agents) AS total_agents,
        (SELECT COUNT(*) FROM events) AS total_events,
        (SELECT COUNT(*) FROM events
          WHERE recorded_at > NOW() - INTERVAL '24 hours'
        ) AS events_today,
        (SELECT COUNT(*) FROM gate_requests
          WHERE status = 'pending'
        ) AS pending_gates,
        (SELECT COUNT(*) FROM anomalies) AS active_anomalies,
        (SELECT COUNT(*) FROM admin_logs
          WHERE created_at > NOW() - INTERVAL '24 hours'
        ) AS admin_actions_today
    `);

    return res.json({
      status: 'ok',
      uptime: Math.floor(process.uptime()),
      redis: redisOk ? 'connected' : 'unavailable',
      stats: stats.rows[0]
    });
  } catch (err) {
    console.error('[admin] GET /health error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ANOMALIES & PATTERNS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/anomalies
adminRouter.get('/anomalies', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        an.id, an.action, an.reason,
        an.detected_at, an.acknowledged,
        a.name AS agent_name, a.did AS agent_did,
        u.email AS owner_email
      FROM anomalies an
      JOIN agents a ON a.id = an.agent_id
      LEFT JOIN users u ON u.id = a.user_id
      ORDER BY an.detected_at DESC
      LIMIT 100
    `);
    return res.json({ anomalies: result.rows });
  } catch (err) {
    console.error('[admin] GET /anomalies error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// GET /v1/admin/patterns
adminRouter.get('/patterns', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        bp.id, bp.pattern_type, bp.action,
        bp.description, bp.occurrences, bp.severity,
        bp.first_seen, bp.last_seen,
        a.name AS agent_name, a.did AS agent_did,
        u.email AS owner_email
      FROM behavior_patterns bp
      JOIN agents a ON a.id = bp.agent_id
      LEFT JOIN users u ON u.id = a.user_id
      WHERE bp.resolved_at IS NULL
      ORDER BY
        CASE bp.severity
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3
          ELSE 4
        END,
        bp.occurrences DESC
      LIMIT 100
    `);
    return res.json({ patterns: result.rows });
  } catch (err) {
    console.error('[admin] GET /patterns error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// WEBHOOKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/webhooks
adminRouter.get('/webhooks', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        w.id, w.url, w.events, w.active,
        w.failure_count, w.last_triggered_at,
        w.created_at, u.email AS owner_email
      FROM webhooks w
      LEFT JOIN users u ON u.id = w.user_id
      ORDER BY w.created_at DESC
    `);
    return res.json({ webhooks: result.rows });
  } catch (err) {
    console.error('[admin] GET /webhooks error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ADMIN AUDIT LOG
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/audit-log
adminRouter.get('/audit-log', async (req, res) => {
  try {
    const result = await query(`
      SELECT id, action, target_type, target_id,
             details, ip_address, created_at
      FROM admin_logs
      ORDER BY created_at DESC
      LIMIT 200
    `);
    return res.json({ logs: result.rows });
  } catch (err) {
    console.error('[admin] GET /audit-log error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DATABASE STATS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /v1/admin/db-stats
adminRouter.get('/db-stats', async (req, res) => {
  try {
    const result = await query(`
      SELECT
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM agents) AS agents,
        (SELECT COUNT(*) FROM events) AS events,
        (SELECT COUNT(*) FROM api_keys) AS api_keys,
        (SELECT COUNT(*) FROM anomalies) AS anomalies,
        (SELECT COUNT(*) FROM gate_requests) AS gate_requests,
        (SELECT COUNT(*) FROM behavior_patterns) AS behavior_patterns,
        (SELECT COUNT(*) FROM temporal_anchors) AS temporal_anchors,
        (SELECT COUNT(*) FROM zero_proofs) AS zero_proofs,
        (SELECT COUNT(*) FROM witness_sources) AS witness_sources,
        (SELECT COUNT(*) FROM witness_checks) AS witness_checks,
        (SELECT COUNT(*) FROM webhooks) AS webhooks,
        (SELECT COUNT(*) FROM admin_logs) AS admin_logs
    `);

    return res.json({
      tables: Object.entries(result.rows[0] || {}).map(
        ([name, count]) => ({ tablename: name, row_count: count })
      )
    });
  } catch (err) {
    console.error('[admin] GET /db-stats error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});
