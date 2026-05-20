export type Plan = 'free' | 'professional' | 'enterprise';

export interface PlanConfig {
  name: string;
  maxAgents: number;
  maxEventsPerMonth: number;
  historyDays: number;
  features: {
    gate: boolean;
    zeroproof: boolean;
    export: boolean;
    webhooks: boolean;
    batchEvents: boolean;
    spectrum: boolean;
    temporalAnchor: boolean;
    shadowWitness: boolean;
    apiAccess: boolean;
  };
}

export const PLANS: Record<Plan, PlanConfig> = {
  free: {
    name: 'Free',
    maxAgents: 1,
    maxEventsPerMonth: 50_000,
    historyDays: 30,
    features: {
      gate: false,
      zeroproof: false,
      export: false,
      webhooks: false,
      batchEvents: false,
      spectrum: true,
      temporalAnchor: false,
      shadowWitness: false,
      apiAccess: true,
    }
  },
  professional: {
    name: 'Professional',
    maxAgents: 5,
    maxEventsPerMonth: 500_000,
    historyDays: 365,
    features: {
      gate: true,
      zeroproof: true,
      export: true,
      webhooks: true,
      batchEvents: true,
      spectrum: true,
      temporalAnchor: true,
      shadowWitness: true,
      apiAccess: true,
    }
  },
  enterprise: {
    name: 'Enterprise',
    maxAgents: Infinity,
    maxEventsPerMonth: Infinity,
    historyDays: Infinity,
    features: {
      gate: true,
      zeroproof: true,
      export: true,
      webhooks: true,
      batchEvents: true,
      spectrum: true,
      temporalAnchor: true,
      shadowWitness: true,
      apiAccess: true,
    }
  }
};

export function getPlanConfig(plan: Plan): PlanConfig {
  return PLANS[plan];
}
