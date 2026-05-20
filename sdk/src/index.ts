import { createHmac } from 'crypto';
import { randomUUID } from 'crypto';

export interface ARIAConfig {
  baseUrl: string;
  apiKey: string;
}

export interface AgentConfig {
  name: string;
  scope: string[];
  meta?: Record<string, unknown>;
}

export interface TrackResult {
  success: boolean;
  eventId: string;
  limitReached?: boolean;
  insights?: {
    scope: { valid: boolean; attempted: string; declared: string[]; message: string };
    signature: { valid: boolean };
    rateLimit: { exceeded: boolean; current: number; limit: number; resetsIn: string };
    trustScore: { impact: number };
  };
}

export interface GateOptions {
  requireApproval?: string[];  // action patterns that need approval
  autoBlock?: string[];        // action patterns always blocked
  timeoutMs?: number;          // how long to wait (default 5 min)
  pollIntervalMs?: number;     // polling interval (default 2 sec)
}

export class GateDeniedException extends Error {
  constructor(
    public readonly requestId: string,
    public readonly action: string
  ) {
    super(`Gate denied: action '${action}' was denied by the owner`);
    this.name = 'GateDeniedException';
  }
}

export class GateBlockedException extends Error {
  constructor(public readonly action: string) {
    super(`Gate blocked: action '${action}' is auto-blocked`);
    this.name = 'GateBlockedException';
  }
}

export class GateTimeoutException extends Error {
  constructor(
    public readonly requestId: string,
    public readonly action: string
  ) {
    super(`Gate timeout: no approval received for '${action}'`);
    this.name = 'GateTimeoutException';
  }
}

export class EventLimitException extends Error {
  public readonly code = 'EVENT_LIMIT_REACHED';
  public readonly currentEvents?: number;
  public readonly maxEvents?: number;

  constructor(
    message: string,
    currentEvents?: number,
    maxEvents?: number
  ) {
    super(message);
    this.name = 'EventLimitException';
    this.currentEvents = currentEvents;
    this.maxEvents = maxEvents;
  }
}

export class ScopeViolationException extends Error {
  public readonly action: string;
  public readonly allowedScope: string[];
  public readonly code = 'SCOPE_VIOLATION';

  constructor(action: string, allowedScope: string[]) {
    super(
      `Action '${action}' is not in the agent's declared scope. ` +
      `Allowed: [${allowedScope.join(', ')}]. ` +
      `Execution blocked by ARIA.`
    );
    this.name = 'ScopeViolationException';
    this.action = action;
    this.allowedScope = allowedScope;
  }
}

export interface TrackOptions {
  mode?: 'light' | 'enforce' | 'gate';
  gate?: GateOptions;
}

const scopeCache = new Map<string, { scope: string[]; cachedAt: number }>();
const SCOPE_CACHE_TTL_MS = 5 * 60 * 1000;

async function getAgentScope(
  agentDid: string,
  apiKey: string,
  baseUrl: string
): Promise<string[]> {
  const cached = scopeCache.get(agentDid);
  if (cached && Date.now() - cached.cachedAt < SCOPE_CACHE_TTL_MS) {
    return cached.scope;
  }
  try {
    const res = await fetch(
      `${baseUrl}/v1/agents/${encodeURIComponent(agentDid)}`,
      { headers: { Authorization: `Bearer ${apiKey}` } }
    );
    if (!res.ok) return [];
    const data = await res.json() as { agent?: { scope?: string[] } };
    const scope = data.agent?.scope ?? [];
    scopeCache.set(agentDid, { scope, cachedAt: Date.now() });
    return scope;
  } catch {
    return [];
  }
}

function actionMatchesScope(action: string, scope: string[]): boolean {
  return scope.some(scopeItem => {
    if (scopeItem === action) return true;
    if (scopeItem.endsWith(':*')) {
      const prefix = scopeItem.slice(0, -1);
      return action.startsWith(prefix);
    }
    return false;
  });
}

export class ARIAClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: ARIAConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
  }

  async registerAgent(config: AgentConfig): Promise<{
    did: string;
    secret: string;
    name: string;
    scope: string[];
  }> {
    const res = await fetch(`${this.baseUrl}/v1/agents`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(config),
    });
    if (!res.ok) throw new Error(`ARIA: Failed to register agent - ${res.status}`);
    const data = await res.json() as { agent: { did: string; name: string; scope: string[] }; secret: string };
    return { did: data.agent.did, secret: data.secret, name: data.agent.name, scope: data.agent.scope };
  }

  async track(
    agentDid: string,
    secret: string,
    action: string,
    fn: () => Promise<unknown>,
    options: TrackOptions = {}
  ): Promise<TrackResult> {
    const mode = options.mode ?? 'enforce';

    if (mode === 'light') {
      // Scope check runs in background — fn() has zero added latency
      getAgentScope(agentDid, this.apiKey, this.baseUrl)
        .then(agentScope => {
          if (agentScope.length > 0 && !actionMatchesScope(action, agentScope)) {
            this.sendBlockedEventBackground(agentDid, secret, action);
          }
        })
        .catch(() => {});

      const startTime = Date.now();
      let outcome: 'success' | 'error' = 'success';
      let fnError: string | undefined;

      try {
        await fn();
      } catch (err) {
        outcome = 'error';
        fnError = err instanceof Error ? err.message : String(err);
      }

      const durationMs = Date.now() - startTime;
      this.sendEventBackground(agentDid, secret, action, outcome, durationMs, fnError);
      return { success: true, eventId: randomUUID() };
    }

    // enforce and gate modes: blocking scope check BEFORE fn()
    const agentScope = await getAgentScope(agentDid, this.apiKey, this.baseUrl);
    if (agentScope.length > 0 && !actionMatchesScope(action, agentScope)) {
      this.sendBlockedEventBackground(agentDid, secret, action);
      throw new ScopeViolationException(action, agentScope);
    }

    if (mode === 'gate' && options.gate) {
      // STEP 1: Check gate BEFORE executing
      await this.gateCheck(
        action,
        agentDid,
        options.gate,
        { action, requestedAt: new Date().toISOString() }
      );
      // If gateCheck throws → fn() never executes

      // STEP 2: Gate approved — now execute fn()
      const startTime = Date.now();
      let outcome: 'success' | 'error' = 'success';
      let fnError: string | undefined;

      try {
        await fn();
      } catch (err) {
        outcome = 'error';
        fnError = err instanceof Error ? err.message : String(err);
      }

      const durationMs = Date.now() - startTime;

      // STEP 3: Record event
      const result = await this.buildAndSendEvent(
        agentDid, secret, action, outcome, durationMs, fnError
      );

      return {
        success: true,
        eventId: result.eventId,
        insights: result.insights
      };
    }

    // enforce mode — blocking, existing behavior
    const start = Date.now();
    let outcome: 'success' | 'error' = 'success';
    let error: string | undefined;

    try {
      await fn();
    } catch (err) {
      outcome = 'error';
      error = err instanceof Error ? err.message : String(err);
    }

    const durationMs = Date.now() - start;
    return this.buildAndSendEvent(agentDid, secret, action, outcome, durationMs, error);
  }

  private async gateCheck(
    action: string,
    agentDid: string,
    options: GateOptions,
    context?: Record<string, unknown>
  ): Promise<void> {
    const timeoutMs = options.timeoutMs ?? 5 * 60 * 1000;
    const pollIntervalMs = options.pollIntervalMs ?? 2000;

    const matchesPattern = (patterns: string[], act: string): boolean => {
      return patterns.some(pattern => {
        if (pattern.endsWith(':*')) {
          const prefix = pattern.slice(0, -1);
          return act.startsWith(prefix);
        }
        return pattern === act;
      });
    };

    // Check auto_block first
    if (options.autoBlock && matchesPattern(options.autoBlock, action)) {
      // Still POST to server for audit trail
      await fetch(`${this.baseUrl}/v1/gate/request`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({ agentDid, action, context })
      });
      throw new GateBlockedException(action);
    }

    // Check requireApproval
    if (!options.requireApproval ||
        !matchesPattern(options.requireApproval, action)) {
      return; // Action doesn't need approval
    }

    // Create gate request
    const requestRes = await fetch(`${this.baseUrl}/v1/gate/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({ agentDid, action, context })
    });

    if (!requestRes.ok) {
      throw new Error(`Gate request failed: ${requestRes.status}`);
    }

    const requestData = await requestRes.json() as {
      requestId: string;
      status: string;
    };

    if (requestData.status === 'auto_blocked') {
      throw new GateBlockedException(action);
    }

    const requestId = requestData.requestId;
    const deadline = Date.now() + timeoutMs;

    // Poll for approval
    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, pollIntervalMs));

      const pollRes = await fetch(
        `${this.baseUrl}/v1/gate/request/${requestId}`,
        {
          headers: { 'Authorization': `Bearer ${this.apiKey}` }
        }
      );

      if (!pollRes.ok) continue;

      const pollData = await pollRes.json() as { status: string };

      if (pollData.status === 'approved') return; // Proceed

      if (pollData.status === 'denied') {
        throw new GateDeniedException(requestId, action);
      }

      if (pollData.status === 'timeout') {
        throw new GateTimeoutException(requestId, action);
      }
      // If still 'pending', keep polling
    }

    throw new GateTimeoutException(requestId, action);
  }

  private sendBlockedEventBackground(
    agentDid: string,
    secret: string,
    action: string
  ): void {
    const eventId = randomUUID();
    const timestamp = new Date().toISOString();
    const payload = `${eventId}:${agentDid}:${action}:blocked:${timestamp}`;
    const signature = createHmac('sha256', secret).update(payload).digest('hex');

    fetch(`${this.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        eventId,
        agentDid,
        action,
        outcome: 'blocked',
        withinScope: false,
        durationMs: 0,
        timestamp,
        signature,
        meta: { blocked_by: 'aria_scope_check' },
      }),
    }).catch(() => {});
  }

  private sendEventBackground(
    agentDid: string,
    secret: string,
    action: string,
    outcome: 'success' | 'error',
    durationMs: number,
    error?: string
  ): void {
    (async () => {
      try {
        await this.buildAndSendEvent(agentDid, secret, action, outcome, durationMs, error);
      } catch (err) {
        if (err instanceof EventLimitException) {
          console.warn(
            '[ARIA] Monthly event limit reached. Events are being dropped. ' +
            'Upgrade your plan at https://ariatrust.org/pricing'
          );
        }
        // All other errors: silently fail — fire and forget
      }
    })();
  }

  private async buildAndSendEvent(
    agentDid: string,
    secret: string,
    action: string,
    outcome: 'success' | 'error',
    durationMs: number,
    error?: string
  ): Promise<TrackResult> {
    const eventId = randomUUID();
    const timestamp = new Date().toISOString();
    const payload = `${eventId}:${agentDid}:${action}:${outcome}:${timestamp}`;
    const signature = createHmac('sha256', secret).update(payload).digest('hex');

    const res = await fetch(`${this.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        eventId,
        agentDid,
        action,
        outcome,
        withinScope: true,
        durationMs,
        timestamp,
        signature,
        error,
      }),
    });

    if (!res.ok) {
      if (res.status === 429) {
        const errorData = await res.json().catch(() => ({})) as {
          code?: string;
          error?: string;
          current_events?: number;
          max_events?: number;
        };
        if (errorData.code === 'EVENT_LIMIT_REACHED') {
          throw new EventLimitException(
            errorData.error ?? 'Monthly event limit reached',
            errorData.current_events,
            errorData.max_events
          );
        }
      }
      return { success: false, eventId };
    }

    const data = await res.json() as { accepted: boolean; eventId: string; insights?: TrackResult['insights'] };
    return { success: data.accepted, eventId: data.eventId, insights: data.insights };
  }

  async getAgent(did: string) {
    const res = await fetch(`${this.baseUrl}/v1/agents/${did}`, {
      headers: { 'Authorization': `Bearer ${this.apiKey}` },
    });
    if (!res.ok) throw new Error(`ARIA: Agent not found`);
    return res.json();
  }

  async listAgents(name?: string) {
    const url = name
      ? `${this.baseUrl}/v1/agents?name=${encodeURIComponent(name)}`
      : `${this.baseUrl}/v1/agents`;
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${this.apiKey}` },
    });
    return res.json();
  }
}

export function createClient(config: ARIAConfig): ARIAClient {
  return new ARIAClient(config);
}

export { wrapTool, wrapTools, createARIACallbackHandler } from './langchain.js';
export type { ARIAToolOptions } from './langchain.js';
