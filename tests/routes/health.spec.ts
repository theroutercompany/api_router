import request from 'supertest';
import { describe, expect, it, afterEach, jest } from '@jest/globals';
import { app } from '../../src/app';

describe('GET /health', () => {
  it('responds with gateway health payload', async () => {
    const response = await request(app).get('/health');

    expect(response.status).toBe(200);
    expect(response.headers['x-request-id']).toBeDefined();
    expect(response.body).toEqual(
      expect.objectContaining({
        status: 'ok',
        uptime: expect.any(Number),
        timestamp: expect.any(String),
      }),
    );
  });
});

describe('GET /readyz', () => {
  type FetchResponse = Awaited<ReturnType<typeof fetch>>;
  const makeResponse = (status: number): FetchResponse =>
    ({ ok: status >= 200 && status < 400, status }) as FetchResponse;

  let fetchSpy: jest.SpiedFunction<typeof fetch> | undefined;

  afterEach(() => {
    if (fetchSpy) {
      fetchSpy.mockRestore();
      fetchSpy = undefined;
    }
  });

  it('reports ready when upstreams are healthy', async () => {
    fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(() => Promise.resolve(makeResponse(200)));

    const response = await request(app).get('/readyz');
    const body = response.body as {
      status: string;
      upstreams: { healthy: boolean }[];
      requestId?: string;
      traceId?: string;
    };

    expect(response.status).toBe(200);
    expect(response.headers['x-request-id']).toBeDefined();
    expect(body.requestId).toBe(response.headers['x-request-id']);
    expect(body.traceId).toBeTruthy();
    expect(body.status).toBe('ready');
    expect(body.upstreams).toHaveLength(2);
    expect(body.upstreams.every((u) => u.healthy)).toBe(true);
  });

  it('reports degraded when any upstream is unhealthy', async () => {
    fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() => Promise.resolve(makeResponse(200)))
      .mockImplementationOnce(() => Promise.resolve(makeResponse(503)));

    const response = await request(app).get('/readyz');
    const body = response.body as {
      status: string;
      upstreams: { healthy: boolean }[];
      requestId?: string;
      traceId?: string;
    };

    expect(response.status).toBe(503);
    expect(response.headers['x-request-id']).toBeDefined();
    expect(body.requestId).toBe(response.headers['x-request-id']);
    expect(body.traceId).toBeTruthy();
    expect(body.status).toBe('degraded');
    expect(body.upstreams.some((u) => !u.healthy)).toBe(true);
  });
});
