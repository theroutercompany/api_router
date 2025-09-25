import { Router } from 'express';
import { getOpenApiDocument } from '../services/openapiService';

const router = Router();

router.get('/openapi.json', async (_req, res, next) => {
  try {
    const document = await getOpenApiDocument();
    res.type('application/json').json(document);
  } catch (error) {
    next(error);
  }
});

export { router as openApiRoutes };
