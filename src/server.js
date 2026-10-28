import app from './app.js';
import { config } from './config/index.js';

const server = app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`🛡️ Link Lens Security Server listening on port ${config.port} [${config.env}]`);
  // eslint-disable-next-line no-console
  console.log(`📡 URL Intelligence Lab & Simulator ready at http://localhost:${config.port}`);
});

function gracefulShutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`\nReceived ${signal}. Shutting down Link Lens gracefully...`);
  server.close(() => {
    // eslint-disable-next-line no-console
    console.log('HTTP server closed.');
    process.exit(0);
  });

  setTimeout(() => {
    // eslint-disable-next-line no-console
    console.error('Forced shutdown due to timeout.');
    process.exit(1);
  }, 5000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

