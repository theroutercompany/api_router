import { app } from './app';
import { env } from './config/env';
import { logger } from './lib/logger';

const start = () => {
  const server = app.listen(env.PORT, () => {
    logger.info(
      { port: env.PORT, env: env.NODE_ENV },
      'API Router Gateway listening',
    );
  });

  server.on('error', (error) => {
    logger.error({ err: error }, 'Unexpected server error');
    process.exit(1);
  });

  return server;
};

if (require.main === module) {
  start();
}

export { start };
