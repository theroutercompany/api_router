import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';

const REQUEST_ID_HEADER = 'x-request-id';
const TRACE_ID_HEADER = 'x-trace-id';

export const requestContext: RequestHandler = (req, res, next) => {
  const headerRequestId = req.header(REQUEST_ID_HEADER);
  const requestId =
    headerRequestId && headerRequestId.length > 0
      ? headerRequestId
      : randomUUID();

  const headerTraceId = req.header(TRACE_ID_HEADER);
  req.requestId = requestId;
  req.traceId = headerTraceId ?? requestId;

  res.locals.requestId = requestId;
  res.locals.traceId = req.traceId;

  res.setHeader(REQUEST_ID_HEADER, requestId);

  if (headerTraceId) {
    res.setHeader(TRACE_ID_HEADER, headerTraceId);
  }

  next();
};
