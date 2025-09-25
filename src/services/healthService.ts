export interface HealthStatus {
  status: 'ok';
  uptime: number;
  timestamp: string;
  version?: string;
}

export const getHealthStatus = (): HealthStatus => ({
  status: 'ok',
  uptime: process.uptime(),
  timestamp: new Date().toISOString(),
  version: process.env.GIT_SHA,
});
