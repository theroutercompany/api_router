#!/usr/bin/env node

import http from 'node:http';

function createServer(port, name) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');

    if (req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', upstream: name }));
      return;
    }

    if (name === 'trade' && url.pathname.startsWith('/v1/trade')) {
      if (url.searchParams.get('simulate') === 'error') {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'trade upstream failure' }));
        return;
      }

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          orderId: '42',
          status: 'confirmed',
        }),
      );
      return;
    }

    if (name === 'task' && url.pathname.startsWith('/v1/task')) {
      if (url.searchParams.get('simulate') === 'timeout') {
        setTimeout(() => {
          res.writeHead(504, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ status: 'timeout' }));
        }, 200);
        return;
      }

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          jobId: 'a1b2',
          state: 'synced',
        }),
      );
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'unknown' }));
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[mock-upstream] ${name} listening on port ${port}`);
  });

  return server;
}

const servers = [
  createServer(4001, 'trade'),
  createServer(4002, 'task'),
];

function shutdown() {
  console.log('[mock-upstream] shutting down');
  for (const server of servers) {
    server.close();
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
