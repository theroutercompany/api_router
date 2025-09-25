import { env } from '../config/env';
import { upstreamServices } from '../config/services';

export interface UpstreamReadiness {
  name: 'trade' | 'task';
  healthy: boolean;
  statusCode?: number;
  error?: string;
  checkedAt: string;
}

export interface GatewayReadinessReport {
  status: 'ready' | 'degraded';
  checkedAt: string;
  upstreams: UpstreamReadiness[];
}

const READINESS_TIMEOUT_MS = env.READINESS_TIMEOUT_MS;
const READINESS_USER_AGENT = 'api-router-gateway/readyz';

const probeUpstream = async (
  name: 'trade' | 'task',
): Promise<UpstreamReadiness> => {
  const upstream = upstreamServices[name];
  const checkedAt = new Date().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, READINESS_TIMEOUT_MS);

  try {
    const targetUrl = new URL(upstream.healthPath, upstream.baseUrl);
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: { 'user-agent': READINESS_USER_AGENT },
      signal: controller.signal,
    });

    return {
      name,
      healthy: response.ok,
      statusCode: response.status,
      checkedAt,
      error: response.ok
        ? undefined
        : `Health check failed with status ${response.status.toString()}`,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error';

    return {
      name,
      healthy: false,
      checkedAt,
      error: reason,
    };
  } finally {
    clearTimeout(timeout);
  }
};

export const buildReadinessReport =
  async (): Promise<GatewayReadinessReport> => {
    const upstreamNames: ('trade' | 'task')[] = ['trade', 'task'];
    const upstreamStatuses = await Promise.all(
      upstreamNames.map((name) => probeUpstream(name)),
    );

    const allHealthy = upstreamStatuses.every((status) => status.healthy);

    return {
      status: allHealthy ? 'ready' : 'degraded',
      checkedAt: new Date().toISOString(),
      upstreams: upstreamStatuses,
    };
  };
