import cors from 'cors';
import type { CorsOptions } from 'cors';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createRouter } from './routes';
import { requestContext } from './middlewares/requestContext';
import { httpLogger } from './middlewares/logging';
import { errorHandler } from './middlewares/errorHandler';
import { NotFoundError } from './lib/errors';
import { env } from './config/env';

const allowedOrigins = env.CORS_ALLOWED_ORIGINS
  ? env.CORS_ALLOWED_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter(Boolean)
  : [];

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    const isAllowed =
      !origin ||
      allowedOrigins.length === 0 ||
      allowedOrigins.includes('*') ||
      allowedOrigins.includes(origin);

    if (isAllowed) {
      callback(null, true);
      return;
    }

    callback(new Error('Not allowed by CORS'));
  },
  optionsSuccessStatus: 204,
};

const rateLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
});

export const app = express();

app.disable('x-powered-by');

app.use(requestContext);
app.use(httpLogger);
app.use(helmet());
app.use(cors(corsOptions));
app.use(rateLimiter);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/', createRouter());

app.use((_req, _res, next) => {
  next(new NotFoundError('Route not found'));
});

app.use(errorHandler);
