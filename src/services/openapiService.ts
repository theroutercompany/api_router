import { readFile, stat, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { merge, isErrorResult, type MergeInput } from 'openapi-merge';
import YAML from 'yaml';
import type { Swagger } from 'atlassian-openapi';
import { ServiceUnavailableError } from '../lib/errors';
import { logger } from '../lib/logger';

const OPENAPI_DIST_PATH = path.join(process.cwd(), 'dist', 'openapi.json');
const OPENAPI_CONFIG_ENV = 'OPENAPI_MERGE_CONFIG_PATH';
const DEFAULT_CONFIG_PATH = path.join(
  process.cwd(),
  'openapi-merge.config.json',
);

interface MergeConfigInput extends Record<string, unknown> {
  inputFile: string;
}

interface MergeConfig {
  inputs: MergeConfigInput[];
}

interface CacheEntry {
  document: Swagger.SwaggerV3;
  mtimeMs: number | null;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isMergeConfigInput = (value: unknown): value is MergeConfigInput =>
  isPlainObject(value) && typeof value.inputFile === 'string';

const isMergeConfig = (value: unknown): value is MergeConfig =>
  isPlainObject(value) &&
  Array.isArray(value.inputs) &&
  value.inputs.every(isMergeConfigInput);

let cache: CacheEntry | null = null;
let inFlight: Promise<Swagger.SwaggerV3> | null = null;

const resolveConfigPath = (): string => {
  return process.env[OPENAPI_CONFIG_ENV] ?? DEFAULT_CONFIG_PATH;
};

const readDistDocument = async (): Promise<Swagger.SwaggerV3> => {
  const stats = await stat(OPENAPI_DIST_PATH);

  if (cache && cache.mtimeMs === stats.mtimeMs) {
    return cache.document;
  }

  const raw = await readFile(OPENAPI_DIST_PATH, 'utf8');
  const document = JSON.parse(raw) as Swagger.SwaggerV3;

  cache = { document, mtimeMs: stats.mtimeMs };
  return document;
};

const parseConfig = async (): Promise<{
  config: MergeConfig;
  baseDir: string;
}> => {
  const configPath = resolveConfigPath();
  const configRaw = await readFile(configPath, 'utf8');
  const parsed = JSON.parse(configRaw) as unknown;

  if (!isMergeConfig(parsed) || parsed.inputs.length === 0) {
    throw new Error('OpenAPI merge configuration has no inputs defined');
  }

  return { config: parsed, baseDir: path.dirname(configPath) };
};

const loadSourceDocument = async (
  inputFile: string,
  baseDir: string,
): Promise<Swagger.SwaggerV3> => {
  const resolvedPath = path.isAbsolute(inputFile)
    ? inputFile
    : path.join(baseDir, inputFile);

  const raw = await readFile(resolvedPath, 'utf8');
  const document: unknown = resolvedPath.endsWith('.json')
    ? JSON.parse(raw)
    : YAML.parse(raw);

  if (!isPlainObject(document)) {
    throw new Error(`OpenAPI source ${resolvedPath} is not a valid object`);
  }

  return document as unknown as Swagger.SwaggerV3;
};

const mergeFromSources = async (): Promise<Swagger.SwaggerV3> => {
  const { config, baseDir } = await parseConfig();

  const inputs = await Promise.all(
    config.inputs.map(async ({ inputFile, ...rest }) => {
      const oas = await loadSourceDocument(inputFile, baseDir);
      const extras = rest as Record<string, unknown>;
      const input = {
        oas,
        ...extras,
      } as MergeInput[number];

      return input;
    }),
  );

  const mergeInput = inputs as MergeInput;

  const result = merge(mergeInput);

  if (isErrorResult(result)) {
    throw new Error(result.message);
  }

  const merged = result.output;

  try {
    await mkdir(path.dirname(OPENAPI_DIST_PATH), { recursive: true });
    await writeFile(OPENAPI_DIST_PATH, JSON.stringify(merged, null, 2));
    cache = { document: merged, mtimeMs: null };
  } catch (error) {
    logger.warn({ err: error }, 'Failed to persist merged OpenAPI document');
    cache = { document: merged, mtimeMs: null };
  }

  return merged;
};

export const getOpenApiDocument = async (): Promise<Swagger.SwaggerV3> => {
  if (inFlight) {
    return inFlight;
  }

  inFlight = (async () => {
    try {
      return await readDistDocument();
    } catch (distError) {
      const error = distError as NodeJS.ErrnoException;

      if (error.code && error.code !== 'ENOENT') {
        logger.warn(
          { err: error },
          'Failed to read OpenAPI document from dist; attempting to rebuild',
        );
      } else {
        logger.debug('OpenAPI document missing; rebuilding from source specs');
      }

      try {
        return await mergeFromSources();
      } catch (mergeError) {
        logger.error({ err: mergeError }, 'Unable to merge OpenAPI documents');

        const detail =
          mergeError instanceof Error ? mergeError.message : 'Unknown error';

        throw new ServiceUnavailableError(
          `Unable to build OpenAPI document: ${detail}`,
        );
      }
    }
  })();

  try {
    const document = await inFlight;
    return document;
  } finally {
    inFlight = null;
  }
};
