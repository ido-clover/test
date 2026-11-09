import https from 'node:https';
import { readFile } from 'node:fs/promises';

export function createSecureServer(app, { key, cert }) {
  return https.createServer({ key, cert, minVersion: 'TLSv1.2' }, app);
}

export async function readTlsConfig(env) {
  if (!env.TLS_KEY_FILE || !env.TLS_CERT_FILE) {
    throw new Error('TLS_KEY_FILE and TLS_CERT_FILE are required');
  }
  const [key, cert] = await Promise.all([readFile(env.TLS_KEY_FILE), readFile(env.TLS_CERT_FILE)]);
  return { key, cert };
}
