import { access, rm } from 'node:fs/promises';
import path from 'node:path';
import type { Express } from 'express';
import request from 'supertest';
import {
  describe,
  expect,
  it,
  afterEach,
  beforeAll,
  afterAll,
  jest,
} from '@jest/globals';
import type * as AppModule from '../../src/app';

const openApiPath = path.join(process.cwd(), 'dist', 'openapi.json');
const originalConfigPath = process.env.OPENAPI_MERGE_CONFIG_PATH;

const buildApp = (): Express => {
  jest.resetModules();
  const appModule = jest.requireActual<typeof AppModule>('../../src/app');
  return appModule.app;
};

describe('OpenAPI document serving', () => {
  beforeAll(async () => {
    await rm(openApiPath, { force: true });
  });

  afterEach(async () => {
    await rm(openApiPath, { force: true });
    if (originalConfigPath) {
      process.env.OPENAPI_MERGE_CONFIG_PATH = originalConfigPath;
    } else {
      delete process.env.OPENAPI_MERGE_CONFIG_PATH;
    }
    jest.resetModules();
  });

  afterAll(() => {
    if (originalConfigPath) {
      process.env.OPENAPI_MERGE_CONFIG_PATH = originalConfigPath;
    } else {
      delete process.env.OPENAPI_MERGE_CONFIG_PATH;
    }
  });

  it('regenerates the merged OpenAPI document when the dist artifact is missing', async () => {
    const app = buildApp();

    const response = await request(app).get('/openapi.json').expect(200);

    const specBody = response.body as unknown;

    if (!specBody || typeof specBody !== 'object') {
      throw new Error('Expected OpenAPI response body to be an object');
    }

    const specRecord = specBody as Record<string, unknown>;
    const openapiVersion = specRecord.openapi;
    const paths = specRecord.paths;

    if (typeof openapiVersion !== 'string') {
      throw new Error('OpenAPI version missing from response');
    }

    expect(openapiVersion.startsWith('3.')).toBe(true);
    expect(paths).toBeDefined();

    await expect(access(openApiPath)).resolves.toBeUndefined();
  });

  it('returns 503 when the merge configuration cannot be loaded', async () => {
    process.env.OPENAPI_MERGE_CONFIG_PATH = path.join(
      process.cwd(),
      'specs',
      'missing-config.json',
    );

    const app = buildApp();

    const response = await request(app).get('/openapi.json').expect(503);

    expect(response.body).toEqual(
      expect.objectContaining({
        title: 'Service Unavailable',
        status: 503,
      }),
    );
  });
});
