process.env.TRADE_API_URL =
  process.env.TRADE_API_URL ?? 'http://localhost:4100';
process.env.TASK_API_URL = process.env.TASK_API_URL ?? 'http://localhost:4200';
process.env.JWT_SECRET =
  process.env.JWT_SECRET ?? 'development-secret-please-change-me-32+';
process.env.JWT_AUDIENCE = process.env.JWT_AUDIENCE ?? 'routers-api';
process.env.JWT_ISSUER = process.env.JWT_ISSUER ?? 'routers.dev';
