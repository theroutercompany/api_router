import { Router } from 'express';
import { upstreamServices } from '../config/services';
import { createGatewayProxy } from '../lib/proxy';
import { authenticate, requireAnyScope } from '../middlewares/authentication';

const router = Router();

router.use(
  '/v1/trade',
  authenticate,
  requireAnyScope(['trade.read', 'trade.write']),
  createGatewayProxy({
    target: upstreamServices.trade.baseUrl,
    product: 'trade',
  }),
);

export { router as tradeRoutes };
