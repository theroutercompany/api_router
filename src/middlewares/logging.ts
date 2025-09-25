import type { IncomingMessage, ServerResponse } from 'http';
import pinoHttp from 'pino-http';
import type { Options } from 'pino-http';
import { logger } from '../lib/logger';

type RequestWithContext = IncomingMessage & {
  requestId?: string;
  traceId?: string;
};

type ResponseWithContext = ServerResponse<RequestWithContext> & {
  req: RequestWithContext;
};

const httpLoggerOptions: Options<RequestWithContext, ResponseWithContext> = {
  logger,
  customProps: (req, res) => ({
    requestId: req.requestId,
    traceId: req.traceId,
    statusCode: res.statusCode,
  }),
  customLogLevel: (_req, res, error) => {
    if (error || res.statusCode >= 500) {
      return 'error';
    }

    if (res.statusCode >= 400) {
      return 'warn';
    }

    return 'info';
  },
};

export const httpLogger = pinoHttp(httpLoggerOptions);
