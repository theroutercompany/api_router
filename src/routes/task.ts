import { Router } from 'express';
import { upstreamServices } from '../config/services';
import { createGatewayProxy } from '../lib/proxy';
import { authenticate, requireAnyScope } from '../middlewares/authentication';

const router = Router();

router.use(
  '/v1/task',
  authenticate,
  requireAnyScope(['task.read', 'task.write']),
  createGatewayProxy({
    target: upstreamServices.task.baseUrl,
    product: 'task',
  }),
);

export { router as taskRoutes };
