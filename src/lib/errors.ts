export interface ProblemJson {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  traceId?: string;
  [key: string]: unknown;
}

export class HttpError extends Error {
  public readonly status: number;

  public readonly title: string;

  public readonly type: string;

  public readonly detail?: string;

  public readonly instance?: string;

  public readonly meta?: Record<string, unknown>;

  constructor(params: {
    status: number;
    title: string;
    type?: string;
    detail?: string;
    instance?: string;
    meta?: Record<string, unknown>;
    cause?: unknown;
  }) {
    super(params.detail ?? params.title, { cause: params.cause });
    this.name = this.constructor.name;
    this.status = params.status;
    this.title = params.title;
    this.type = params.type ?? 'about:blank';
    this.detail = params.detail;
    this.instance = params.instance;
    this.meta = params.meta;
  }

  toProblemJson(traceId?: string): ProblemJson {
    return {
      type: this.type,
      title: this.title,
      status: this.status,
      detail: this.detail,
      instance: this.instance,
      traceId,
      ...this.meta,
    };
  }
}

export class NotFoundError extends HttpError {
  constructor(detail?: string) {
    super({ status: 404, title: 'Resource Not Found', detail });
  }
}

export class UnauthorizedError extends HttpError {
  constructor(detail?: string) {
    super({ status: 401, title: 'Authentication Required', detail });
  }
}

export class ForbiddenError extends HttpError {
  constructor(detail?: string) {
    super({ status: 403, title: 'Insufficient Scope', detail });
  }
}

export class BadRequestError extends HttpError {
  constructor(detail?: string, meta?: Record<string, unknown>) {
    super({ status: 400, title: 'Bad Request', detail, meta });
  }
}

export class ServiceUnavailableError extends HttpError {
  constructor(detail?: string) {
    super({ status: 503, title: 'Service Unavailable', detail });
  }
}

export function asHttpError(error: unknown): HttpError {
  if (error instanceof HttpError) {
    return error;
  }

  if (error instanceof Error) {
    return new HttpError({
      status: 500,
      title: 'Internal Server Error',
      detail: error.message,
      cause: error,
    });
  }

  return new HttpError({ status: 500, title: 'Internal Server Error' });
}
