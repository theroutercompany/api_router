import type { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { ForbiddenError, UnauthorizedError } from '../lib/errors';
import { logger } from '../lib/logger';

type JwtPayload = jwt.JwtPayload & {
  scope?: string;
  scp?: string[];
};

const AUTH_HEADER = 'authorization';

const parseScopes = (payload: JwtPayload): string[] => {
  if (Array.isArray(payload.scp)) {
    return payload.scp;
  }

  if (typeof payload.scope === 'string') {
    return payload.scope.split(' ').filter(Boolean);
  }

  return [];
};

export const authenticate: RequestHandler = (req, _res, next) => {
  const secret = env.JWT_SECRET;

  if (!secret) {
    logger.error(
      { requestId: req.requestId },
      'JWT secret not configured; authentication cannot proceed',
    );
    next(new UnauthorizedError('Gateway authentication is not configured'));
    return;
  }

  const header = req.header(AUTH_HEADER);

  if (!header) {
    next(new UnauthorizedError('Missing authorization header'));
    return;
  }

  const [scheme, token] = header.split(' ');
  const normalizedScheme = (scheme || '').toLowerCase();

  if (normalizedScheme !== 'bearer' || !token) {
    next(new UnauthorizedError('Malformed authorization header'));
    return;
  }

  try {
    const payload = jwt.verify(token, secret, {
      audience: env.JWT_AUDIENCE,
      issuer: env.JWT_ISSUER,
    }) as JwtPayload;

    req.auth = {
      subject: typeof payload.sub === 'string' ? payload.sub : 'unknown',
      scopes: parseScopes(payload),
      token,
    };

    next();
  } catch (error) {
    const cause =
      error instanceof Error ? error : new Error('JWT verification failed');
    logger.warn(
      { err: cause, requestId: req.requestId },
      'JWT verification failed',
    );
    next(new UnauthorizedError('Invalid or expired token'));
  }
};

export const requireScopes = (requiredScopes: string[]): RequestHandler => {
  return (req, _res, next) => {
    if (!req.auth) {
      next(new UnauthorizedError('Authentication required'));
      return;
    }

    const missingScopes = requiredScopes.filter(
      (scope) => !req.auth?.scopes.includes(scope),
    );

    if (missingScopes.length > 0) {
      next(new ForbiddenError(`Missing scopes: ${missingScopes.join(', ')}`));
      return;
    }

    next();
  };
};

export const requireAnyScope = (scopes: string[]): RequestHandler => {
  return (req, _res, next) => {
    if (!req.auth) {
      next(new UnauthorizedError('Authentication required'));
      return;
    }

    const hasScope = scopes.some((scope) => req.auth?.scopes.includes(scope));

    if (!hasScope) {
      next(new ForbiddenError(`Requires one of scopes: ${scopes.join(', ')}`));
      return;
    }

    next();
  };
};
