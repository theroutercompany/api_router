import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Express } from 'express';
import type * as AppModule from '../../src/app';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { describe, expect, it, beforeAll, afterAll, jest } from '@jest/globals';

interface RecordedRequest {
  url?: string;
  method?: string;
  headers: http.IncomingHttpHeaders;
}

describe('Proxy routing', () => {
  let app: Express;
  let tradeServer: http.Server;
  let taskServer: http.Server;
  let tradeRequests: RecordedRequest[];
  let taskRequests: RecordedRequest[];
  let originalTradeUrl: string | undefined;
  let originalTaskUrl: string | undefined;
  let tradeToken: string;
  let taskToken: string;

  const startStubServer = async (
    label: string,
    requests: RecordedRequest[],
  ) => {
    const server = http.createServer((req, res) => {
      requests.push({
        url: req.url ?? undefined,
        method: req.method ?? undefined,
        headers: req.headers,
      });

      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          upstream: label,
          path: req.url,
          headers: req.headers,
        }),
      );
    });

    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        resolve();
      });
    });

    return server;
  };

  beforeAll(async () => {
    tradeRequests = [];
    taskRequests = [];

    tradeServer = await startStubServer('trade', tradeRequests);
    taskServer = await startStubServer('task', taskRequests);

    const tradePort = (tradeServer.address() as AddressInfo).port;
    const taskPort = (taskServer.address() as AddressInfo).port;

    originalTradeUrl = process.env.TRADE_API_URL;
    originalTaskUrl = process.env.TASK_API_URL;

    process.env.TRADE_API_URL = `http://127.0.0.1:${tradePort.toString()}`;
    process.env.TASK_API_URL = `http://127.0.0.1:${taskPort.toString()}`;

    jest.resetModules();

    const appModule = jest.requireActual<typeof AppModule>('../../src/app');
    app = appModule.app;

    const baseClaims = {
      iss: process.env.JWT_ISSUER,
      aud: process.env.JWT_AUDIENCE,
      sub: 'test-user',
    };

    const secret =
      process.env.JWT_SECRET ?? 'development-secret-please-change-me-32+';

    tradeToken = jwt.sign(
      {
        ...baseClaims,
        scope: 'trade.read trade.write',
      },
      secret,
      { expiresIn: '5m' },
    );

    taskToken = jwt.sign(
      {
        ...baseClaims,
        scope: 'task.read task.write',
      },
      secret,
      { expiresIn: '5m' },
    );
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      tradeServer.close(() => {
        resolve();
      });
    });
    await new Promise<void>((resolve) => {
      taskServer.close(() => {
        resolve();
      });
    });

    process.env.TRADE_API_URL = originalTradeUrl;
    process.env.TASK_API_URL = originalTaskUrl;
  });

  it('forwards /v1/trade requests to the trade backend', async () => {
    const response = await request(app)
      .get('/v1/trade/orders?id=42')
      .set('authorization', `Bearer ${tradeToken}`)
      .expect(200);

    expect(response.body).toEqual(
      expect.objectContaining({
        upstream: 'trade',
        path: '/v1/trade/orders?id=42',
      }),
    );

    const lastRequest = tradeRequests.at(-1);
    expect(lastRequest?.url).toBe('/v1/trade/orders?id=42');
    expect(lastRequest?.headers['x-router-product']).toBe('trade');
    expect(lastRequest?.headers['x-request-id']).toBeDefined();
  });

  it('forwards /v1/task requests to the task backend', async () => {
    const response = await request(app)
      .post('/v1/task/jobs')
      .send({ id: 'job-123' })
      .set('authorization', `Bearer ${taskToken}`)
      .expect(200);

    expect(response.body).toEqual(
      expect.objectContaining({ upstream: 'task', path: '/v1/task/jobs' }),
    );

    const lastRequest = taskRequests.at(-1);
    expect(lastRequest?.method).toBe('POST');
    expect(lastRequest?.headers['x-router-product']).toBe('task');
    expect(lastRequest?.headers['x-request-id']).toBeDefined();
  });
});
