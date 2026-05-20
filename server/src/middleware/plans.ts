import {
  type Request, type Response, type NextFunction
} from 'express';
import { query } from '../db/pool.js';
import { PLANS, type Plan } from '../config/plans.js';

interface UserPlan {
  plan: Plan;
  userId: string;
}

type ReqWithUser = Request & { userId?: string; plan?: Plan };

export async function getUserPlan(
  apiKeyId: string
): Promise<UserPlan | null> {
  const result = await query<{
    user_id: string;
    plan: Plan;
  }>(`
    SELECT u.id AS user_id, u.plan
    FROM api_keys ak
    JOIN users u ON u.email = ak.owner_email
    WHERE ak.id = $1
      AND ak.revoked_at IS NULL
  `, [apiKeyId]);

  if (!result.rows[0]) return null;
  return {
    plan: result.rows[0].plan,
    userId: result.rows[0].user_id
  };
}

async function getMonthlyEventCount(
  userId: string
): Promise<number> {
  const month = new Date().toISOString().slice(0, 7);

  const result = await query<{ event_count: string }>(
    `SELECT event_count FROM usage_stats
     WHERE user_id = $1 AND month = $2`,
    [userId, month]
  );

  return parseInt(result.rows[0]?.event_count ?? '0');
}

export async function incrementEventCount(
  userId: string,
  count: number = 1
): Promise<void> {
  const month = new Date().toISOString().slice(0, 7);

  await query(`
    INSERT INTO usage_stats (user_id, month, event_count)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, month) DO UPDATE SET
      event_count = usage_stats.event_count + $3,
      updated_at = NOW()
  `, [userId, month, count]);
}

// ── MIDDLEWARE FACTORIES ──────────────────────────────

export function requireFeature(
  feature: keyof typeof PLANS['free']['features']
) {
  return async (
    req: Request, res: Response, next: NextFunction
  ): Promise<void> => {
    try {
      const userPlan = await getUserPlan(req.apiKeyId);
      if (!userPlan) {
        res.status(401).json({
          error: 'Unauthorized', code: 'UNAUTHORIZED'
        });
        return;
      }

      const planConfig = PLANS[userPlan.plan];
      if (!planConfig.features[feature]) {
        res.status(403).json({
          error: `${feature} requires a Professional plan or higher.`,
          code: 'PLAN_LIMIT',
          feature,
          current_plan: userPlan.plan,
          upgrade_url: 'https://ariatrust.org/pricing'
        });
        return;
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

export async function checkAgentLimit(
  req: Request, res: Response, next: NextFunction
): Promise<void> {
  try {
    const userPlan = await getUserPlan(req.apiKeyId);
    if (!userPlan) {
      res.status(401).json({
        error: 'Unauthorized', code: 'UNAUTHORIZED'
      });
      return;
    }

    const planConfig = PLANS[userPlan.plan];
    if (planConfig.maxAgents === Infinity) {
      next();
      return;
    }

    const countResult = await query<{ count: string }>(
      `SELECT COUNT(*) AS count FROM agents
       WHERE user_id = $1`,
      [userPlan.userId]
    );

    const currentAgents = parseInt(
      countResult.rows[0]?.count ?? '0'
    );

    if (currentAgents >= planConfig.maxAgents) {
      res.status(403).json({
        error: `Your ${planConfig.name} plan allows up to ` +
          `${planConfig.maxAgents} agent(s). ` +
          `You have ${currentAgents}. ` +
          `Upgrade to add more agents.`,
        code: 'AGENT_LIMIT_REACHED',
        current_plan: userPlan.plan,
        max_agents: planConfig.maxAgents,
        current_agents: currentAgents,
        upgrade_url: 'https://ariatrust.org/pricing'
      });
      return;
    }

    next();
  } catch (err) {
    next(err);
  }
}

export async function checkEventLimit(
  req: Request, res: Response, next: NextFunction
): Promise<void> {
  try {
    const userPlan = await getUserPlan(req.apiKeyId);
    if (!userPlan) {
      res.status(401).json({
        error: 'Unauthorized', code: 'UNAUTHORIZED'
      });
      return;
    }

    const planConfig = PLANS[userPlan.plan];
    if (planConfig.maxEventsPerMonth === Infinity) {
      (req as ReqWithUser).userId = userPlan.userId;
      next();
      return;
    }

    const currentCount = await getMonthlyEventCount(
      userPlan.userId
    );

    if (currentCount >= planConfig.maxEventsPerMonth) {
      res.status(429).json({
        error: `Monthly event limit reached. ` +
          `Your ${planConfig.name} plan allows ` +
          `${planConfig.maxEventsPerMonth.toLocaleString()} ` +
          `events per month. ` +
          `You have used ${currentCount.toLocaleString()}.`,
        code: 'EVENT_LIMIT_REACHED',
        current_plan: userPlan.plan,
        max_events: planConfig.maxEventsPerMonth,
        current_events: currentCount,
        upgrade_url: 'https://ariatrust.org/pricing'
      });
      return;
    }

    (req as ReqWithUser).userId = userPlan.userId;
    next();
  } catch (err) {
    next(err);
  }
}
