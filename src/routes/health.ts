import { Router } from 'express';
import { getHealth, getReadiness } from '../controllers/healthController';

const router = Router();

router.get('/health', getHealth);
router.get('/readyz', getReadiness);

export { router as healthRoutes };
