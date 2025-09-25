import 'express-serve-static-core';

declare global {
  namespace Express {
    interface Request {
      requestId: string;
      traceId?: string;
      auth?: {
        subject: string;
        scopes: string[];
        token: string;
      };
    }

    interface Locals extends Record<string, unknown> {
      requestId?: string;
      traceId?: string;
    }
  }
}

export {};
