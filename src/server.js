import { createApp } from './app.js';
import { createSecureServer, readTlsConfig } from './transport.js';

try {
  const tlsConfig = await readTlsConfig(process.env);
  const app = await createApp();
  createSecureServer(app, tlsConfig).listen(Number(process.env.PORT ?? 3000));
} catch {
  console.error('Unable to start application. Check environment configuration.');
  process.exitCode = 1;
}
