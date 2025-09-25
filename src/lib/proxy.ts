import type { Request, Response } from 'express';
import type { ClientRequest } from 'node:http';
import { Socket } from 'node:net';
import { createProxyMiddleware } from 'http-proxy-middleware';
import type { Options } from 'http-proxy-middleware';
import type { RequestHandler } from 'express';
import { logger } from './logger';

export interface GatewayProxyOptions {
  target: string;
  product: 'trade' | 'task';
}

const GATEWAY_TIMEOUT_MS = 30_000;

const respondWithUpstreamError = (
  res: Response,
  req: Request,
  product: string,
  error: Error,
) => {
  if (res.headersSent) {
    res.end();
    return;
  }

  const traceId = req.traceId ?? req.headers['x-trace-id'];
  const body = {
    type: 'about:blank',
    title: 'Upstream Service Unavailable',
    status: 502,
    detail: `Failed to reach ${product} service`,
    traceId,
    instance: req.originalUrl,
  };

  logger.error(
    { err: error, requestId: req.requestId, traceId },
    'Proxy upstream failure',
  );

  res.status(502).json(body);
};

export const createGatewayProxy = ({
  target,
  product,
}: GatewayProxyOptions): RequestHandler => {
  const options: Options<Request, Response> = {
    target,
    changeOrigin: true,
    xfwd: true,
    proxyTimeout: GATEWAY_TIMEOUT_MS,
    timeout: GATEWAY_TIMEOUT_MS,
    pathRewrite: (_path, req) => req.originalUrl,
    on: {
      proxyReq: (proxyReq: ClientRequest, req: Request) => {
        const clientRequest = proxyReq;
        const request = req;

        if (request.requestId) {
          clientRequest.setHeader('x-request-id', request.requestId);
        }

        if (request.traceId) {
          clientRequest.setHeader('x-trace-id', request.traceId);
        }

        clientRequest.setHeader('x-router-product', product);
      },
      error: (err: Error, req: Request, res: Response | Socket) => {
        if (res instanceof Socket) {
          if (!res.destroyed) {
            res.destroy(err);
          }

          return;
        }

        respondWithUpstreamError(res, req, product, err);
      },
    },
  };

  return createProxyMiddleware<Request, Response>(options);
};
