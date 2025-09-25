import type { RequestHandler } from 'express';
import { getHealthStatus } from '../services/healthService';
import { buildReadinessReport } from '../services/readinessService';

export const getHealth: RequestHandler = (_req, res) => {
  const body = getHealthStatus();
  return res.status(200).json(body);
};

export const getReadiness: RequestHandler = async (req, res, next) => {
  try {
    const report = await buildReadinessReport();
    const statusCode = report.status === 'ready' ? 200 : 503;

    res.status(statusCode).json({
      ...report,
      requestId: req.requestId,
      traceId: req.traceId ?? req.requestId,
    });
  } catch (error) {
    next(error);
  }
};
