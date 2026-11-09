import { randomBytes, scrypt } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
const HASH_BYTES = 64;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function validCredentials(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === 2
    && Object.hasOwn(value, 'username') && Object.hasOwn(value, 'password')
    && typeof value.username === 'string' && value.username.length > 0
    && value.username.length <= 128
    && typeof value.password === 'string' && value.password.length > 0
    && value.password.length <= 1024;
}

export function hashPassword(password, salt) {
  return derive(password, salt, HASH_BYTES, SCRYPT_OPTIONS);
}

export async function createUsers(username, password) {
  if (!validCredentials({ username, password })) {
    throw new Error('Valid SEED_USERNAME and SEED_PASSWORD are required');
  }
  const salt = randomBytes(16);
  const passwordHash = await hashPassword(password, salt);
  return new Map([['1', { id: '1', username, salt, passwordHash }]]);
}

export async function createSeedUsers(env = process.env) {
  const users = await createUsers(env.SEED_USERNAME, env.SEED_PASSWORD);
  if (env.SEED_EMAIL) users.get('1').email = env.SEED_EMAIL;
  return users;
}
