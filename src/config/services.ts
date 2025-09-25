import { env } from './env';

export interface UpstreamServiceConfig {
  name: 'trade' | 'task';
  baseUrl: string;
  healthPath: string;
}

export const upstreamServices: Record<'trade' | 'task', UpstreamServiceConfig> =
  {
    trade: {
      name: 'trade',
      baseUrl: env.TRADE_API_URL,
      healthPath: env.TRADE_HEALTH_PATH,
    },
    task: {
      name: 'task',
      baseUrl: env.TASK_API_URL,
      healthPath: env.TASK_HEALTH_PATH,
    },
  };
