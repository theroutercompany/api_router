import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
    .default('info'),
  JWT_AUDIENCE: z.string().min(1).optional(),
  JWT_ISSUER: z.string().min(1).optional(),
  JWT_SECRET: z.string().min(32).optional(),
  TRADE_API_URL: z
    .string()
    .pipe(z.url({ message: 'TRADE_API_URL must be a valid URL' })),
  TASK_API_URL: z
    .string()
    .pipe(z.url({ message: 'TASK_API_URL must be a valid URL' })),
  TRADE_HEALTH_PATH: z.string().default('/health'),
  TASK_HEALTH_PATH: z.string().default('/health'),
  READINESS_TIMEOUT_MS: z.coerce.number().int().positive().default(2_000),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),
  CORS_ALLOWED_ORIGINS: z.string().optional(),
});

type EnvInput = z.input<typeof envSchema>;
type Env = z.infer<typeof envSchema>;

function loadEnv(input: EnvInput = process.env as EnvInput): Env {
  const parsed = envSchema.safeParse(input);

  if (!parsed.success) {
    console.error('Invalid environment configuration', parsed.error.issues);
    throw new Error('Invalid environment variables. See logs for details.');
  }

  return parsed.data;
}

export const env = loadEnv();
export type { Env, EnvInput };
