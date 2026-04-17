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
    fn: () => Promise<unknown>
  ): Promise<TrackResult> {
    const eventId = randomUUID();
    const timestamp = new Date().toISOString();
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

    return { success: res.ok, eventId };
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