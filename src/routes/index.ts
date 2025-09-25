import { Router } from 'express';
import { healthRoutes } from './health';
import { tradeRoutes } from './trade';
import { taskRoutes } from './task';
import { openApiRoutes } from './openapi';

export const createRouter = (): Router => {
  const router = Router();

  router.use('/', healthRoutes);
  router.use('/', tradeRoutes);
  router.use('/', taskRoutes);
  router.use('/', openApiRoutes);

  return router;
};
