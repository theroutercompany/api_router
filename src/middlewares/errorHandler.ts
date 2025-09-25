import type { ErrorRequestHandler } from 'express';
import { asHttpError } from '../lib/errors';
import { logger } from '../lib/logger';

export const errorHandler: ErrorRequestHandler = (error, req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  const httpError = asHttpError(error);
  const traceId = req.traceId ?? req.requestId;
  const logError =
    error instanceof Error
      ? error
      : new Error('Unknown error', {
          cause: error,
        });
  const logContext = { err: logError, requestId: req.requestId, traceId };

  if (httpError.status >= 500) {
    logger.error(logContext, httpError.title);
  } else {
    logger.warn(logContext, httpError.title);
  }

  res.status(httpError.status).json(httpError.toProblemJson(traceId));
};
