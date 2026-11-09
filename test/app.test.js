import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import session from 'express-session';
import supertest from 'supertest';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import { MemoryStore } from 'express-rate-limit';
import { createApp } from '../src/app.js';
import { createUsers } from '../src/seed.js';
import { createSecureServer, readTlsConfig } from '../src/transport.js';

const credentials = { username: 'demo', password: ` ${randomBytes(24).toString('hex')} ` };
const env = { SESSION_SECRET: randomBytes(48).toString('hex') };
const unauthorized = { error: 'Unauthorized' };
const internalError = { error: 'Internal server error' };
let seededUsers;
let tlsConfig;
let certificateDirectory;
before(async () => {
  seededUsers = await createUsers(credentials.username, credentials.password);
  certificateDirectory = await mkdtemp(join(tmpdir(), 'kura-login-tls-'));
  const keyFile = join(certificateDirectory, 'key.pem');
  const certFile = join(certificateDirectory, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout', keyFile, '-out', certFile], { stdio: 'ignore' });
  tlsConfig = { key: await readFile(keyFile), cert: await readFile(certFile) };
});
after(async () => { if (certificateDirectory) await rm(certificateDirectory, { recursive: true, force: true }); });

function request(app) {
  const client = supertest(createSecureServer(app, tlsConfig));
  return {
    get: (...args) => client.get(...args).ca(tlsConfig.cert),
    post: (...args) => client.post(...args).ca(tlsConfig.cert),
    delete: (...args) => client.delete(...args).ca(tlsConfig.cert),
  };
}

async function fixture(options = {}) {
  const store = options.store ?? new session.MemoryStore();
  const users = new Map([...seededUsers].map(([id, user]) => [id, { ...user }]));
  const app = await createApp({ env, store, users, audit: () => {}, ...options });
  return { app, store, users };
}
async function csrf(app, cookie) {
  let req = request(app).get('/csrf-token');
  if (cookie) req = req.set('Cookie', cookie);
  const res = await req.expect(200);
  return { cookie: res.headers['set-cookie'] ? cookieOf(res) : cookie, token: res.body.csrfToken };
}
async function sendLogin(app, body, status, cookie, contentType = 'application/json') {
  const context = await csrf(app, cookie);
  return request(app).post('/login').set('Cookie', context.cookie)
    .set('X-CSRF-Token', context.token).set('Content-Type', contentType).send(body).expect(status);
}
const login = (app) => sendLogin(app, credentials, 200);
const cookieOf = (res) => res.headers['set-cookie'][0].split(';')[0];
const savedSession = (store) => {
  const [id] = Object.keys(store.sessions);
  return { id, data: JSON.parse(store.sessions[id]) };
};
function assertCleared(res) {
  const cookie = res.headers['set-cookie'].find((value) => value.startsWith('sid='));
  assert.match(cookie, /^sid=;/);
  assert.match(cookie, /Expires=Thu, 01 Jan 1970/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
}

test('/health returns ok without authentication and requires HTTPS', async () => {
  const { app, store } = await fixture();
  const response = await request(app).get('/health').expect(200).expect('Content-Type', /text\/plain/);
  assert.equal(response.text, 'ok');
  assert.equal(response.headers['set-cookie'], undefined);
  assert.deepEqual(Object.keys(store.sessions), []);
  const insecure = await supertest(app).get('/health').expect(400);
  assert.deepEqual(insecure.body, { error: 'HTTPS required' });
});

test('/version returns the package version without authentication and requires HTTPS', async () => {
  const { app, store } = await fixture();
  const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const response = await request(app).get('/version').expect(200).expect('Content-Type', /application\/json/);
  assert.deepEqual(response.body, { version });
  assert.equal(response.headers['set-cookie'], undefined);
  assert.deepEqual(Object.keys(store.sessions), []);
  const insecure = await supertest(app).get('/version').expect(400);
  assert.deepEqual(insecure.body, { error: 'HTTPS required' });
});

test('avatar download requires authentication, CSRF and a trusted image URL, then saves the user file', async (t) => {
  const username = `avatar-${randomBytes(12).toString('hex')}`;
  const path = `./uploads/${username}.png`;
  t.after(() => rm(path, { force: true }));
  const users = await createUsers(username, credentials.password);
  const { app } = await fixture({ users,
    env: { ...env, AVATAR_ALLOWED_ORIGINS: 'https://images.example' } });
  const image = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64');
  const download = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url.href, 'https://images.example/avatar.png');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    return new Response(image, { headers: { 'Content-Type': 'image/png' } });
  });
  const endpoint = '/api/profile/avatar';
  const body = { url: 'https://images.example/avatar.png' };
  await request(app).post(endpoint).send(body).expect(401);
  const cookie = cookieOf(await sendLogin(app, { ...credentials, username }, 200));
  await request(app).post(endpoint).set('Cookie', cookie).send(body).expect(403);
  const context = await csrf(app, cookie);
  const send = (payload) => request(app).post(endpoint).set('Cookie', cookie)
    .set('X-CSRF-Token', context.token).send(payload);
  for (const payload of [{}, { url: 1 }, { url: 'http://127.0.0.1/private' },
    { url: 'https://images.example.evil/avatar.png' }, { url: 'https://user:pass@images.example/avatar.png' }]) {
    await send(payload).expect(400);
  }
  users.get('1').username = '../escape';
  await send(body).expect(400);
  users.get('1').username = username;
  assert.equal(download.mock.callCount(), 0);
  const response = await send(body).expect(200);
  assert.deepEqual(response.body, { path });
  assert.deepEqual(await readFile(path), image);
  download.mock.mockImplementation(async () => new Response('not an image'));
  await send(body).expect(502);
  download.mock.mockImplementation(async () => new Response(Buffer.alloc(2 * 1024 * 1024 + 1),
    { headers: { 'Content-Type': 'image/png' } }));
  await send(body).expect(502);
  download.mock.mockImplementation(async () => { throw new Error('redirect or network failure'); });
  await send(body).expect(502);
  assert.deepEqual(await readFile(path), image);
});

test('login sets cookie and /me returns only public fields; passwords are not trimmed', async () => {
  const { app, store } = await fixture();
  const response = await login(app);
  assert.deepEqual(response.body, { id: '1', username: credentials.username });
  const cookie = response.headers['set-cookie'][0];
  assert.match(cookie, /^sid=/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Secure/);
  assert.equal(response.headers['strict-transport-security'], 'max-age=31536000');
  const { data } = savedSession(store);
  assert.deepEqual(Object.keys(data).sort(), ['cookie', 'csrfToken', 'userId']);
  assert.ok(Math.abs(new Date(data.cookie.expires).getTime() - Date.now() - 3600000) < 3000);
  assert.deepEqual((await request(app).get('/me').set('Cookie', cookieOf(response)).expect(200)).body, response.body);
  await sendLogin(app, { ...credentials, password: credentials.password.trim() }, 401);
});

test('/admin/users rejects unauthenticated requests', async () => {
  const { app } = await fixture();
  for (const cookie of [undefined, 'sid=invalid']) {
    let req = request(app).get('/admin/users');
    if (cookie) req = req.set('Cookie', cookie);
    const response = await req.expect(401);
    assert.deepEqual(response.body, unauthorized);
    assert.equal(response.headers['cache-control'], 'no-store');
    assertCleared(response);
  }
});

test('/api/admin/users requires a current admin session and lists email and successful login times', async () => {
  let time = Date.parse('2026-11-08T10:00:00.000Z');
  const { app, users } = await fixture({ now: () => time });
  const path = '/api/admin/users';
  const denied = await request(app).get(path).expect(401);
  assert.equal(denied.headers['cache-control'], 'no-store');
  const cookie = cookieOf(await login(app));
  const lastLogin = new Date(time).toISOString();
  time += 1000;
  await sendLogin(app, { ...credentials, password: 'incorrect' }, 401);
  assert.equal(users.get('1').lastLogin, lastLogin);
  await request(app).get(path).set('Cookie', cookie).expect(403);
  users.get('1').role = 'admin';
  users.set('2', { id: '2', username: 'other', email: 'other@example.test',
    lastLogin: '2026-11-01T12:00:00.000Z', passwordHash: randomBytes(64), salt: randomBytes(16) });
  users.set('3', { id: '3', username: 'never-logged-in' });
  const response = await request(app).get(path).set('Cookie', cookie).expect(200);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.deepEqual(response.body, [
    { username: credentials.username, email: null, lastLogin },
    { username: 'other', email: 'other@example.test', lastLogin: '2026-11-01T12:00:00.000Z' },
    { username: 'never-logged-in', email: null, lastLogin: null },
  ]);
  users.get('1').role = 'user';
  await request(app).get(path).set('Cookie', cookie).expect(403);
  users.get('1').role = 'admin';
  users.get('1').credentialVersion = randomBytes(32).toString('hex');
  await request(app).get(path).set('Cookie', cookie).expect(401);
});

test('DELETE /api/admin/users/:id requires an admin session and deletes the user', async () => {
  const { app, users } = await fixture();
  users.set('2', { id: '2', username: 'other' });
  const denied = await request(app).delete('/api/admin/users/2').expect(401);
  assert.deepEqual(denied.body, unauthorized);
  const cookie = cookieOf(await login(app));
  const forbidden = await request(app).delete('/api/admin/users/2').set('Cookie', cookie).expect(403);
  assert.deepEqual(forbidden.body, { error: 'Forbidden' });
  assert.ok(users.has('2'));
  users.get('1').role = 'admin';
  await request(app).delete('/api/admin/users/2').set('Cookie', cookie).expect(204);
  assert.ok(!users.has('2'));
  const missing = await request(app).delete('/api/admin/users/999').set('Cookie', cookie).expect(404);
  assert.deepEqual(missing.body, { error: 'Not found' });
});

test('/admin/users denies missing and non-admin roles, including client role spoofing', async () => {
  const { app, users } = await fixture();
  const cookie = cookieOf(await login(app));
  for (const role of [undefined, 'user', 'Admin', true]) {
    users.get('1').role = role;
    const response = await request(app).get('/admin/users?role=admin')
      .set('Cookie', cookie).set('X-Role', 'admin').expect(403);
    assert.deepEqual(response.body, { error: 'Forbidden' });
    assert.equal(response.headers['cache-control'], 'no-store');
  }
  await sendLogin(app, { ...credentials, role: 'admin' }, 400);
});

test('/admin/users lists only public user fields for admins and honors role revocation', async () => {
  const { app, users } = await fixture();
  users.get('1').role = 'admin';
  users.set('2', { id: '2', username: 'other', role: 'user',
    salt: randomBytes(16), passwordHash: randomBytes(64), credentialVersion: 'private' });
  const cookie = cookieOf(await login(app));
  const response = await request(app).get('/admin/users').set('Cookie', cookie).expect(200);
  assert.deepEqual(response.body, [{ id: '1', username: credentials.username }, { id: '2', username: 'other' }]);
  assert.equal(response.headers['cache-control'], 'no-store');
  users.get('1').role = 'user';
  await request(app).get('/admin/users').set('Cookie', cookie).expect(403);
});

test('/admin/users rejects expired, credential-revoked and deleted admin sessions', async () => {
  for (const state of ['expired', 'revoked', 'deleted']) {
    const { app, store, users } = await fixture();
    users.get('1').role = 'admin';
    const cookie = cookieOf(await login(app));
    const { id, data } = savedSession(store);
    if (state === 'expired') {
      data.cookie.expires = new Date(Date.now() - 1000).toISOString();
      store.sessions[id] = JSON.stringify(data);
    } else if (state === 'revoked') users.get('1').credentialVersion = randomBytes(32).toString('hex');
    else users.delete('1');
    const response = await request(app).get('/admin/users').set('Cookie', cookie).expect(401);
    assert.deepEqual(response.body, unauthorized);
    assertCleared(response);
    assert.equal(store.sessions[id], undefined);
  }
});

test('/admin/users audits successful and denied access without user or session data', async () => {
  const events = [];
  let recordSuccess;
  const recordedSuccess = new Promise((resolve) => { recordSuccess = resolve; });
  const { app, users } = await fixture({ audit: (entry) => {
    events.push(entry);
    if (entry.event === 'admin_users_success') recordSuccess();
  } });
  await request(app).get('/admin/users').expect(401);
  const cookie = cookieOf(await login(app));
  await request(app).get('/admin/users').set('Cookie', cookie).expect(403);
  users.get('1').role = 'admin';
  await request(app).get('/admin/users').set('Cookie', cookie).expect(200);
  await recordedSuccess;
  assert.deepEqual(events.map(({ event }) => event), [
    'admin_users_denied', 'login_success', 'admin_users_denied', 'admin_users_success',
  ]);
  for (const entry of events) {
    assert.deepEqual(Object.keys(entry).sort(), ['event', 'timestamp']);
    assert.ok(Number.isFinite(Date.parse(entry.timestamp)));
  }
});

const exportPath = (id) => `/api/users/${id}/export`;
const secretFields = ['salt', 'passwordHash', 'credentialVersion'];
function assertNoSecrets(response, record) {
  for (const field of secretFields) assert.equal(Object.hasOwn(response.body, field), false);
  for (const value of [record.salt, record.passwordHash]) {
    for (const encoding of ['hex', 'base64']) assert.ok(!response.text.includes(value.toString(encoding)));
  }
}

test('user export downloads the owner record as JSON without authenticators', async () => {
  const time = Date.parse('2026-11-08T10:00:00.000Z');
  const { app, users } = await fixture({ now: () => time });
  users.get('1').email = 'demo@example.test';
  users.get('1').credentialVersion = randomBytes(32).toString('hex');
  const cookie = cookieOf(await login(app));
  const response = await request(app).get(exportPath('1')).set('Cookie', cookie).expect(200)
    .expect('Content-Type', /^application\/json/);
  assert.equal(response.headers['content-disposition'], 'attachment; filename=user-1.json');
  assert.equal(response.headers['strict-transport-security'], 'max-age=31536000');
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.deepEqual(response.body, { id: '1', username: credentials.username,
    email: 'demo@example.test', lastLogin: new Date(time).toISOString() });
  assertNoSecrets(response, users.get('1'));
  assert.ok(!response.text.includes(users.get('1').credentialVersion));
});

test('user export rejects absent, expired, credential-revoked and deleted sessions', async () => {
  for (const state of ['absent', 'expired', 'revoked', 'deleted']) {
    const { app, store, users } = await fixture();
    const cookie = cookieOf(await login(app));
    const { id, data } = savedSession(store);
    if (state === 'expired') {
      data.cookie.expires = new Date(Date.now() - 1000).toISOString();
      store.sessions[id] = JSON.stringify(data);
    } else if (state === 'revoked') users.get('1').credentialVersion = randomBytes(32).toString('hex');
    else if (state === 'deleted') users.delete('1');
    let req = request(app).get(exportPath('1'));
    if (state !== 'absent') req = req.set('Cookie', cookie);
    const response = await req.expect(401);
    assert.deepEqual(response.body, unauthorized);
    assert.equal(response.headers['cache-control'], 'no-store');
    assertCleared(response);
    if (state !== 'absent') assert.equal(store.sessions[id], undefined);
  }
});

test('user export forbids non-admins from other ids without looking them up', async (t) => {
  const { app, users } = await fixture();
  users.set('2', { id: '2', username: 'other', email: 'other@example.test',
    salt: randomBytes(16), passwordHash: randomBytes(64) });
  const cookie = cookieOf(await login(app));
  const lookups = t.mock.method(users, 'get');
  for (const role of [undefined, 'user', 'Admin']) {
    users.get('1').role = role;
    for (const id of ['2', '999']) {
      const response = await request(app).get(exportPath(id)).set('Cookie', cookie)
        .set('X-Role', 'admin').expect(403);
      assert.deepEqual(response.body, { error: 'Forbidden' });
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.equal(response.headers['content-disposition'], undefined);
    }
  }
  assert.ok(lookups.mock.callCount() > 0);
  for (const call of lookups.mock.calls) assert.ok(!['2', '999'].includes(call.arguments[0]));
});

test('user export lets admins export other users and returns 404 for unknown ids', async () => {
  const { app, users } = await fixture();
  users.get('1').role = 'admin';
  users.set('2', { id: '2', username: 'other', email: 'other@example.test', role: 'user',
    lastLogin: '2026-11-01T12:00:00.000Z', salt: randomBytes(16), passwordHash: randomBytes(64),
    credentialVersion: randomBytes(32).toString('hex') });
  const cookie = cookieOf(await login(app));
  const response = await request(app).get(exportPath('2')).set('Cookie', cookie).expect(200)
    .expect('Content-Type', /^application\/json/);
  assert.equal(response.headers['content-disposition'], 'attachment; filename=user-2.json');
  assert.deepEqual(response.body, { id: '2', username: 'other', email: 'other@example.test',
    role: 'user', lastLogin: '2026-11-01T12:00:00.000Z' });
  assertNoSecrets(response, users.get('2'));
  assert.ok(!response.text.includes(users.get('2').credentialVersion));
  const missing = await request(app).get(exportPath('999')).set('Cookie', cookie).expect(404);
  assert.deepEqual(missing.body, { error: 'Not found' });
  assert.equal(missing.headers['content-disposition'], undefined);
});

test('user export requires HTTPS', async () => {
  const { app } = await fixture();
  const response = await supertest(app).get(exportPath('1')).set('X-Forwarded-Proto', 'https').expect(400);
  assert.deepEqual(response.body, { error: 'HTTPS required' });
  assert.equal(response.headers['set-cookie'], undefined);
});

test('user export audits allowed and denied access without user or record data', async () => {
  const events = [];
  let recordSuccess;
  const recordedSuccess = new Promise((resolve) => { recordSuccess = resolve; });
  const { app, users } = await fixture({ audit: (entry) => {
    events.push(entry);
    if (entry.event === 'user_export_success') recordSuccess();
  } });
  users.set('2', { id: '2', username: 'other' });
  await request(app).get(exportPath('1')).expect(401);
  const cookie = cookieOf(await login(app));
  await request(app).get(exportPath('2')).set('Cookie', cookie).expect(403);
  users.get('1').role = 'admin';
  await request(app).get(exportPath('999')).set('Cookie', cookie).expect(404);
  await request(app).get(exportPath('1')).set('Cookie', cookie).expect(200);
  await recordedSuccess;
  assert.deepEqual(events.map(({ event }) => event), [
    'user_export_denied', 'login_success', 'user_export_denied', 'user_export_denied', 'user_export_success',
  ]);
  for (const entry of events) {
    assert.deepEqual(Object.keys(entry).sort(), ['event', 'timestamp']);
    assert.ok(Number.isFinite(Date.parse(entry.timestamp)));
  }
});

test('seed records contain unique salts and hashes, never plaintext', async () => {
  const first = seededUsers.get('1');
  const second = (await createUsers(credentials.username, credentials.password)).get('1');
  assert.deepEqual(Object.keys(first).sort(), ['id', 'passwordHash', 'salt', 'username']);
  assert.equal(first.salt.length, 16);
  assert.equal(first.passwordHash.length, 64);
  assert.notDeepEqual(first.salt, second.salt);
  assert.notDeepEqual(first.passwordHash, second.passwordHash);
});

test('login strictly validates request structure and length', async () => {
  const { app } = await fixture({ loginLimit: { limit: 100 } });
  const invalid = [null, [], {}, { username: 'demo' }, { ...credentials, extra: true },
    { ...credentials, username: '' }, { ...credentials, password: '' },
    { ...credentials, username: 42 }, { ...credentials, password: {} },
    { ...credentials, username: 'x'.repeat(129) }, { ...credentials, password: 'x'.repeat(1025) }];
  for (const input of invalid) {
    const res = await sendLogin(app, JSON.stringify(input), 400);
    assert.deepEqual(res.body, { error: 'Bad request' });
  }
  for (const body of ['{', JSON.stringify({ ...credentials, password: 'x'.repeat(17000) })]) {
    assert.deepEqual((await sendLogin(app, body, 400)).body, { error: 'Bad request' });
  }
  await sendLogin(app, 'username=demo', 400, undefined, 'application/x-www-form-urlencoded');
});

test('unknown usernames and incorrect passwords return identical failures', async () => {
  const { app } = await fixture();
  const wrong = await sendLogin(app, { ...credentials, password: randomBytes(8).toString('hex') }, 401);
  const unknown = await sendLogin(app, { ...credentials, username: 'unknown' }, 401);
  assert.deepEqual(wrong.body, unauthorized);
  assert.deepEqual(unknown.body, wrong.body);
  assert.equal(wrong.headers['set-cookie'], undefined);
  assert.equal(unknown.headers['set-cookie'], undefined);
});

test('/me uniformly rejects absent, malformed, tampered, expired and orphaned sessions', async () => {
  const { app, store, users } = await fixture();
  for (const cookie of [undefined, 'sid=invalid', 'sid=%E0%A4%A']) {
    let req = request(app).get('/me');
    if (cookie) req = req.set('Cookie', cookie);
    const res = await req.expect(401);
    assert.deepEqual(res.body, unauthorized);
    assertCleared(res);
  }
  const valid = cookieOf(await login(app));
  const tampered = valid.slice(0, -2) + 'xx';
  assert.deepEqual((await request(app).get('/me').set('Cookie', tampered).expect(401)).body, unauthorized);
  const { id, data } = savedSession(store);
  data.cookie.expires = new Date(Date.now() - 1000).toISOString();
  store.sessions[id] = JSON.stringify(data);
  const expired = await request(app).get('/me').set('Cookie', valid).expect(401);
  assert.deepEqual(expired.body, unauthorized);
  assertCleared(expired);
  assert.equal(store.sessions[id], undefined);
  const orphanCookie = cookieOf(await login(app));
  const orphanId = savedSession(store).id;
  users.clear();
  const orphan = await request(app).get('/me').set('Cookie', orphanCookie).expect(401);
  assert.deepEqual(orphan.body, unauthorized);
  assertCleared(orphan);
  assert.equal(store.sessions[orphanId], undefined);
});

test('login replaces the prior session and invalidates its cookie', async () => {
  const { app, store } = await fixture();
  const oldCookie = cookieOf(await login(app));
  const oldId = savedSession(store).id;
  const fresh = await sendLogin(app, credentials, 200, oldCookie);
  assert.notEqual(cookieOf(fresh), oldCookie);
  assert.equal(store.sessions[oldId], undefined);
  await request(app).get('/me').set('Cookie', oldCookie).expect(401);
  await request(app).get('/me').set('Cookie', cookieOf(fresh)).expect(200);
});

test('logout destroys backend session, clears cookie, and is idempotent', async () => {
  const { app, store } = await fixture();
  const cookie = cookieOf(await login(app));
  const { id } = savedSession(store);
  const context = await csrf(app, cookie);
  assertCleared(await request(app).post('/logout').set('Cookie', cookie).set('X-CSRF-Token', context.token).expect(204));
  assert.equal(store.sessions[id], undefined);
  await request(app).get('/me').set('Cookie', cookie).expect(401);
  assertCleared(await request(app).post('/logout').set('Cookie', cookie).expect(204));
  assertCleared(await request(app).post('/logout').expect(204));
  assertCleared(await request(app).post('/logout').set('Cookie', 'sid=invalid').expect(204));
});

test('session get, save, regeneration and logout destroy failures return generic 500', async () => {
  for (const operation of ['get', 'set', 'regenerate', 'orphan', 'logout']) {
    const { app, store, users } = await fixture();
    const cookie = cookieOf(await login(app));
    const context = await csrf(app, cookie);
    const error = new Error('sensitive backend detail');
    if (operation === 'get') store.get = (id, cb) => cb(error);
    else if (operation === 'set') store.set = (id, value, cb) => cb(error);
    else store.destroy = (id, cb) => cb(error);
    if (operation === 'orphan') users.clear();
    let req;
    if (operation === 'get' || operation === 'orphan') req = request(app).get('/me');
    else if (operation === 'logout') req = request(app).post('/logout');
    else req = request(app).post('/login').send(credentials);
    const res = await req.set('Cookie', cookie).set('X-CSRF-Token', context.token).expect(500);
    assert.deepEqual(res.body, internalError);
    assertCleared(res);
    assert.ok(res.headers['set-cookie'].every((value) => value.startsWith('sid=;')));
  }
});

test('production requires a secret, enables Secure cookies, and trusts proxies only explicitly', async () => {
  for (const secret of [undefined, '', ' ']) {
    await assert.rejects(createApp({ env: { NODE_ENV: 'production', SESSION_SECRET: secret }, users: seededUsers }), /SESSION_SECRET/);
  }
  const { app } = await fixture({ env: { ...env, NODE_ENV: 'production', TRUST_PROXY_HOPS: '1' } });
  const res = await login(app);
  assert.match(res.headers['set-cookie'][0], /; Secure/);
  const context = await csrf(app, cookieOf(res));
  const logout = await request(app).post('/logout').set('X-Forwarded-Proto', 'https').set('Cookie', cookieOf(res)).set('X-CSRF-Token', context.token).expect(204);
  assertCleared(logout);
  assert.match(logout.headers['set-cookie'][0], /; Secure/);
  const untrusted = await fixture({ env: { ...env, NODE_ENV: 'production' } });
  const insecure = await supertest(untrusted.app).post('/login').set('X-Forwarded-Proto', 'https').send(credentials).expect(400);
  assert.deepEqual(insecure.body, { error: 'HTTPS required' });
  assert.equal(insecure.headers['set-cookie'], undefined);
  assert.equal(untrusted.app.get('trust proxy'), false);
  await assert.rejects(createApp({ env: { ...env, TRUST_PROXY_HOPS: 'true' }, users: seededUsers }), /TRUST_PROXY_HOPS/);
});

test('startup requires seed credentials and local sessions work with a generated secret', async () => {
  await assert.rejects(createApp({ env: {} }), /SEED_USERNAME/);
  const app = await createApp({ env: { SEED_USERNAME: credentials.username, SEED_PASSWORD: credentials.password }, audit: () => {} });
  const cookie = cookieOf(await login(app));
  await request(app).get('/me').set('Cookie', cookie).expect(200);
});

test('login rate limit rejects attempts with generic 429 and standard headers', async () => {
  const { app } = await fixture();
  for (let count = 0; count < 10; count++) {
    await sendLogin(app, count % 2 ? '{}' : '{', 400);
  }
  const limited = await sendLogin(app, credentials, 429);
  assert.deepEqual(limited.body, { error: 'Too many requests' });
  assert.ok(limited.headers.ratelimit);
  assert.ok(limited.headers['ratelimit-policy']);
  assert.ok(limited.headers['retry-after']);
  assert.equal(limited.headers['x-ratelimit-limit'], undefined);
  await request(app).get('/me').expect(401);
  await request(app).post('/logout').expect(204);
});

test('resetting rate-limit counters permits login again', async () => {
  const store = new MemoryStore();
  const { app } = await fixture({ loginLimit: { store, limit: 1 } });
  await sendLogin(app, {}, 400);
  await sendLogin(app, credentials, 429);
  await store.resetAll();
  await login(app);
});

test('TLS startup fails closed and connections below TLS 1.2 are rejected', async () => {
  await assert.rejects(readTlsConfig({}), /TLS_KEY_FILE/);
  const { app } = await fixture();
  const server = createSecureServer(app, tlsConfig);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(new Promise((resolve, reject) => {
      const socket = tls.connect({ host: '127.0.0.1', port: server.address().port,
        ca: tlsConfig.cert, minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' });
      socket.once('secureConnect', () => { socket.destroy(); resolve(); });
      socket.once('error', reject);
    }));
    const res = await supertest(server).get('/me').ca(tlsConfig.cert).expect(401);
    assert.equal(res.headers['strict-transport-security'], 'max-age=31536000');
    await assert.rejects(supertest(`http://127.0.0.1:${server.address().port}`).get('/me'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('rotated secrets accept old cookies only while previous secret remains configured', async () => {
  const { app, store, users } = await fixture();
  const oldCookie = cookieOf(await login(app));
  const currentSecret = randomBytes(48).toString('hex');
  const rotated = await createApp({ env: { SESSION_SECRET: currentSecret, SESSION_SECRET_PREVIOUS: env.SESSION_SECRET }, store, users, audit: () => {} });
  await request(rotated).get('/me').set('Cookie', oldCookie).expect(200);
  const withoutPrevious = await createApp({ env: { SESSION_SECRET: currentSecret }, store, users, audit: () => {} });
  await request(withoutPrevious).get('/me').set('Cookie', oldCookie).expect(401);
  const freshCookie = cookieOf(await login(rotated));
  await request(withoutPrevious).get('/me').set('Cookie', freshCookie).expect(200);
  await request(app).get('/me').set('Cookie', freshCookie).expect(401);
});

test('audit events contain only event names and timestamps', async () => {
  const events = [];
  const { app, store } = await fixture({ audit: (event) => events.push(event), loginLimit: { limit: 2 } });
  await sendLogin(app, { ...credentials, password: 'wrong' }, 401);
  const cookie = cookieOf(await login(app));
  await sendLogin(app, credentials, 429);
  const context = await csrf(app, cookie);
  await request(app).post('/logout').set('Cookie', cookie).set('X-CSRF-Token', context.token).expect(204);
  store.get = (id, callback) => callback(new Error('sensitive backend detail'));
  await request(app).get('/me').set('Cookie', cookie).expect(500);
  assert.deepEqual(events.map(({ event }) => event), ['login_failure', 'login_success', 'login_rate_limited', 'logout', 'session_error']);
  for (const event of events) {
    assert.deepEqual(Object.keys(event).sort(), ['event', 'timestamp']);
    assert.ok(Number.isFinite(Date.parse(event.timestamp)));
  }
  const output = JSON.stringify(events);
  for (const sensitive of [credentials.username, credentials.password, env.SESSION_SECRET, cookie, 'sensitive backend detail']) {
    assert.ok(!output.includes(sensitive));
  }
});


test('login CSRF rejects missing, malformed, query-only and cross-session tokens', async () => {
  const { app } = await fixture({ loginLimit: { limit: 100 } });
  const first = await csrf(app);
  const second = await csrf(app);
  assert.match(first.token, /^[a-f0-9]{64}$/);
  assert.notEqual(first.token, second.token);
  for (const token of [undefined, '', 'x', 'a'.repeat(64), second.token]) {
    let req = request(app).post('/login').set('Cookie', first.cookie).send(credentials);
    if (token !== undefined) req = req.set('X-CSRF-Token', token);
    assert.deepEqual((await req.expect(403)).body, { error: 'Forbidden' });
  }
  await request(app).post('/login').set('X-CSRF-Token', first.token).send(credentials).expect(403);
  await request(app).post(`/login?_csrf=${first.token}`).set('Cookie', first.cookie).send(credentials).expect(403);
  await request(app).post('/login').set('Cookie', first.cookie).send({ ...credentials, _csrf: [first.token] }).expect(403);
  await request(app).get('/me').set('Cookie', first.cookie).expect(401);
});

test('login rotates token and session; authenticated logout requires the current token', async () => {
  const { app, store } = await fixture();
  const before = await csrf(app);
  const oldId = savedSession(store).id;
  const response = await request(app).post('/login').set('Cookie', before.cookie)
    .set('X-CSRF-Token', before.token).send(credentials).expect(200);
  const cookie = cookieOf(response);
  assert.notEqual(cookie, before.cookie);
  assert.equal(store.sessions[oldId], undefined);
  const current = await csrf(app, cookie);
  assert.notEqual(current.token, before.token);
  for (const token of [undefined, before.token, 'a'.repeat(64)]) {
    let req = request(app).post('/logout').set('Cookie', cookie);
    if (token) req = req.set('X-CSRF-Token', token);
    await req.expect(403);
    await request(app).get('/me').set('Cookie', cookie).expect(200);
  }
  await request(app).post('/login').set('Cookie', cookie).set('X-CSRF-Token', before.token).send(credentials).expect(403);
  await request(app).post('/login').set('Cookie', before.cookie).set('X-CSRF-Token', before.token).send(credentials).expect(403);
  assertCleared(await request(app).post('/logout').set('Cookie', cookie)
    .set('X-CSRF-Token', current.token).expect(204));
  await request(app).get('/me').set('Cookie', cookie).expect(401);
});

test('HTML login and logout forms submit successfully with uncacheable session-bound tokens', async () => {
  const { app } = await fixture();
  const form = await request(app).get('/login').expect(200).expect('Content-Type', /html/);
  assert.equal(form.headers['cache-control'], 'no-store');
  assert.match(form.text, /<form method="post" action="\/login">/);
  assert.match(form.text, /type="password"/);
  const token = form.text.match(/name="_csrf" value="([a-f0-9]{64})"/)[1];
  const response = await request(app).post('/login').set('Cookie', cookieOf(form)).type('form')
    .send({ ...credentials, _csrf: token }).expect(303).expect('Location', '/account');
  const cookie = cookieOf(response);
  const account = await request(app).get('/account').set('Cookie', cookie).expect(200);
  assert.equal(account.headers['cache-control'], 'no-store');
  const logoutToken = account.text.match(/name="_csrf" value="([a-f0-9]{64})"/)[1];
  assert.notEqual(logoutToken, token);
  const apiToken = await request(app).get('/csrf-token').set('Cookie', cookie).expect(200);
  assert.equal(apiToken.headers['cache-control'], 'no-store');
  assert.equal(apiToken.body.csrfToken, logoutToken);
  assertCleared(await request(app).post('/logout').set('Cookie', cookie).type('form')
    .send({ _csrf: logoutToken }).expect(303).expect('Location', '/login'));
  await request(app).get('/account').set('Cookie', cookie).expect(303).expect('Location', '/login');
});

test('audit records every login rejection, including parser, CSRF, TLS, aliases and store failures', async () => {
  const events = [];
  const { app, store } = await fixture({ audit: (event) => events.push(event) });
  const context = await csrf(app);
  for (const path of ['/login', '/login/', '/LOGIN']) {
    await request(app).post(path).send(credentials).expect(403);
  }
  await request(app).post('/login').set('Content-Type', 'application/json').send('{').expect(400);
  await supertest(app).post('/login').send(credentials).expect(400);
  store.get = (id, callback) => callback(new Error('sensitive backend detail'));
  await request(app).post('/login').set('Cookie', context.cookie)
    .set('X-CSRF-Token', context.token).send(credentials).expect(500);
  assert.equal(events.filter(({ event }) => event === 'login_failure').length, 6);
  assert.equal(events.filter(({ event }) => event === 'session_error').length, 1);
  for (const event of events) assert.deepEqual(Object.keys(event).sort(), ['event', 'timestamp']);
  const output = JSON.stringify(events);
  for (const sensitive of [context.token, context.cookie, credentials.username, credentials.password, 'sensitive backend detail']) {
    assert.ok(!output.includes(sensitive));
  }
});

const resetRequestPath = '/reset/request';
const resetPath = '/reset/confirm';
async function sendReset(app, path, body, status, context) {
  context ??= await csrf(app);
  return request(app).post(path).set('Cookie', context.cookie)
    .set('X-CSRF-Token', context.token).set('Content-Type', 'application/json').send(body).expect(status);
}
async function resetFixture(options = {}) {
  const deliveries = [];
  const setup = await fixture({ sendPasswordReset: (entry) => deliveries.push(entry), ...options });
  const issue = async () => {
    await sendReset(setup.app, resetRequestPath, { username: credentials.username }, 202);
    return deliveries.at(-1).token;
  };
  return { ...setup, deliveries, issue };
}

test('email reset logs a relative link, resets seeded credentials once, expires tokens and revokes sessions', async (t) => {
  const links = [];
  t.mock.method(console, 'info', (link) => links.push(link));
  let time = Date.now();
  const events = [];
  let recordedSuccess;
  const success = new Promise((resolve) => { recordedSuccess = resolve; });
  const email = 'demo@example.test';
  const app = await createApp({ env: { ...env, SEED_USERNAME: credentials.username,
    SEED_PASSWORD: credentials.password, SEED_EMAIL: email }, now: () => time,
  audit: (entry) => { events.push(entry); if (entry.event === 'password_reset_success') recordedSuccess(); } });
  const cookie = cookieOf(await login(app));
  const context = await csrf(app);
  const response = await request(app).post('/api/password-reset').set('Cookie', context.cookie)
    .set('X-CSRF-Token', context.token).set('X-Forwarded-Host', 'attacker.example').send({ email }).expect(202);
  assert.equal(response.headers['cache-control'], 'no-store');
  const unknown = await sendReset(app, '/api/password-reset', { email: 'unknown@example.test' }, 202);
  assert.deepEqual(unknown.body, response.body);
  assert.equal(links.length, 1);
  assert.match(links[0], /^\/api\/password-reset\/confirm\?token=[a-f0-9]{64}$/);
  const token = new URL(links[0], 'https://example.test').searchParams.get('token');
  assert.ok(!JSON.stringify(response.body).includes(token));
  const password = ` ${randomBytes(24).toString('hex')} `;
  await sendReset(app, '/api/password-reset/confirm', { token, password }, 204);
  await success;
  await sendReset(app, '/api/password-reset/confirm', { token, password }, 400);
  await request(app).get('/me').set('Cookie', cookie).expect(401);
  await sendLogin(app, credentials, 401);
  await sendLogin(app, { ...credentials, password }, 200);
  await sendReset(app, '/api/password-reset', { email }, 202);
  const expired = new URL(links[1], 'https://example.test').searchParams.get('token');
  time += 15 * 60 * 1000;
  await sendReset(app, '/api/password-reset/confirm', { token: expired, password }, 400);
  for (const entry of events) assert.deepEqual(Object.keys(entry).sort(), ['event', 'timestamp']);
  assert.ok(events.some(({ event }) => event === 'password_reset_requested'));
  for (const secret of [email, token, expired, password]) assert.ok(!JSON.stringify(events).includes(secret));
});

test('email reset validates inputs and requires CSRF while sharing the legacy reset limiter', async () => {
  const { app } = await fixture({ resetLimit: { limit: 100 }, logResetLink: () => assert.fail('unexpected link') });
  for (const [path, good, invalid] of [
    ['/api/password-reset', { email: 'demo@example.test' }, [{}, { email: null }, { email: 1 },
      { email: 'bad' }, { email: 'a@b' }, { email: 'a\n@example.test' }, { email: `${'a'.repeat(245)}@example.test` },
      { email: 'demo@example.test', username: 'demo' }]],
    ['/api/password-reset/confirm', { token: 'a'.repeat(64), password: 'new' }, [{}, { token: 'bad', password: 'new' },
      { token: 'a'.repeat(64), password: '' }, { token: 'a'.repeat(64), password: 1 }]],
  ]) {
    await request(app).post(path).send(good).expect(403);
    const context = await csrf(app);
    for (const body of invalid) await sendReset(app, path, body, 400, context);
    await request(app).post(path).set('Content-Type', 'application/json').send('{').expect(400);
    await supertest(app).post(path).send(good).expect(400);
  }
  const limited = await fixture({ resetLimit: { limit: 2 } });
  await request(limited.app).post('/api/password-reset').expect(403);
  await request(limited.app).post('/api/password-reset/confirm').expect(403);
  const response = await request(limited.app).post('/reset/request').expect(429);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.ok(response.headers.ratelimit);
});

test('email reset matches only stored emails and revokes tokens if link logging fails', async () => {
  const links = [];
  const events = [];
  const { app, users } = await fixture({ logResetLink: (link) => {
    links.push(link);
    throw new Error('logger unavailable');
  }, audit: (entry) => events.push(entry) });
  const email = 'demo@example.test';
  const absent = await sendReset(app, '/api/password-reset', { email }, 202);
  assert.equal(links.length, 0);
  users.get('1').email = email;
  const failed = await sendReset(app, '/api/password-reset', { email }, 202);
  assert.deepEqual(failed.body, absent.body);
  assert.equal(links.length, 1);
  const token = new URL(links[0], 'https://example.test').searchParams.get('token');
  await sendReset(app, '/api/password-reset/confirm', { token, password: 'new' }, 400);
  assert.ok(events.some(({ event }) => event === 'password_reset_delivery_failed'));
});

test('password reset delivers privately, changes salted hash, and revokes all prior sessions', async () => {
  const events = [];
  const { app, users, deliveries, issue } = await resetFixture({ audit: (event) => events.push(event) });
  const cookies = [cookieOf(await login(app)), cookieOf(await login(app))];
  const oldHash = users.get('1').passwordHash;
  const oldSalt = users.get('1').salt;
  const token = await issue();
  assert.match(token, /^[a-f0-9]{64}$/);
  assert.deepEqual(deliveries[0].user, { id: '1', username: credentials.username });
  assert.ok(Date.parse(deliveries[0].expiresAt) > Date.now());
  const unknown = await sendReset(app, resetRequestPath, { username: 'unknown' }, 202);
  assert.equal(deliveries.length, 1);
  assert.ok(!JSON.stringify(unknown.body).includes(token));
  assert.equal(unknown.headers['cache-control'], 'no-store');
  const password = ` ${randomBytes(24).toString('hex')} `;
  await sendReset(app, resetPath, { token, password }, 204);
  assert.notDeepEqual(users.get('1').passwordHash, oldHash);
  assert.notDeepEqual(users.get('1').salt, oldSalt);
  for (const cookie of cookies) {
    await request(app).get('/account').set('Cookie', cookie).expect(303).expect('Location', '/login');
    await request(app).get('/me').set('Cookie', cookie).expect(401);
  }
  await sendLogin(app, credentials, 401);
  await sendLogin(app, { ...credentials, password: password.trim() }, 401);
  const fresh = await sendLogin(app, { ...credentials, password }, 200);
  await request(app).get('/me').set('Cookie', cookieOf(fresh)).expect(200);
  await request(app).get('/account').set('Cookie', cookieOf(fresh)).expect(200);
  await sendReset(app, resetPath, { token, password }, 400);
  for (const event of events) assert.deepEqual(Object.keys(event).sort(), ['event', 'timestamp']);
  assert.ok(events.some(({ event }) => event === 'password_reset_success'));
  assert.ok(!JSON.stringify(events).includes(token));
  assert.ok(!JSON.stringify(events).includes(password));
});

test('password reset rejects unknown, superseded, expired and concurrent token redemption', async () => {
  let time = Date.now();
  const { app, issue } = await resetFixture({ now: () => time, resetLimit: { limit: 100 } });
  const old = await issue();
  const token = await issue();
  assert.notEqual(old, token);
  const password = randomBytes(24).toString('hex');
  const unknown = await sendReset(app, resetPath, { token: randomBytes(32).toString('hex'), password }, 400);
  const superseded = await sendReset(app, resetPath, { token: old, password }, 400);
  assert.deepEqual(superseded.body, unknown.body);
  time += 15 * 60 * 1000;
  const expired = await sendReset(app, resetPath, { token, password }, 400);
  assert.deepEqual(expired.body, unknown.body);
  const current = await issue();
  const contexts = await Promise.all([csrf(app), csrf(app)]);
  const responses = await Promise.all(contexts.map((context) => request(app).post(resetPath)
    .set('Cookie', context.cookie).set('X-CSRF-Token', context.token).send({ token: current, password })));
  assert.deepEqual(responses.map(({ status }) => status).sort(), [204, 400]);
});

test('password reset strictly validates payloads and requires session-bound CSRF on both endpoints', async () => {
  const { app, issue } = await resetFixture({ resetLimit: { limit: 100 } });
  const token = await issue();
  for (const [path, good, invalid] of [
    [resetRequestPath, { username: credentials.username }, [{}, [], null, { username: '' }, { username: 1 },
      { username: 'x'.repeat(129) }, { username: 'demo', extra: true }]],
    [resetPath, { token, password: credentials.password }, [{}, [], null, { token }, { token, password: '' },
      { token, password: 1 }, { token, password: 'x'.repeat(1025) }, { token: 'x', password: 'ok' },
      { token, password: 'ok', extra: true }]],
  ]) {
    const context = await csrf(app);
    const other = await csrf(app);
    for (const csrfToken of [undefined, 'x', other.token]) {
      let req = request(app).post(path).set('Cookie', context.cookie).send(good);
      if (csrfToken !== undefined) req = req.set('X-CSRF-Token', csrfToken);
      await req.expect(403);
    }
    await request(app).post(`${path}?_csrf=${context.token}`).set('Cookie', context.cookie).send(good).expect(403);
    for (const body of invalid) {
      const response = await sendReset(app, path, JSON.stringify(body), 400, context);
      assert.deepEqual(response.body, { error: 'Bad request' });
    }
    await request(app).post(path).set('Content-Type', 'application/json').send('{').expect(400);
  }
  await sendReset(app, resetPath, { token, password: randomBytes(24).toString('hex') }, 204);
});

test('reset endpoints share an independent rate limit including malformed requests before parsing', async () => {
  const { app } = await resetFixture({ resetLimit: { limit: 2 } });
  await request(app).post(resetRequestPath).set('Content-Type', 'application/json').send('{').expect(400);
  await request(app).post(resetPath).expect(403);
  const limited = await request(app).post(resetRequestPath).set('Content-Type', 'application/json').send('{').expect(429);
  assert.deepEqual(limited.body, { error: 'Too many requests' });
  assert.ok(limited.headers.ratelimit);
  assert.ok(limited.headers['retry-after']);
  await login(app);
});

test('reset delivery must be configured, and failed delivery revokes tokens without exposing accounts', async () => {
  const disabled = await fixture();
  for (const username of [credentials.username, 'unknown']) {
    await sendReset(disabled.app, resetRequestPath, { username }, 503);
  }
  const events = [];
  let failedToken;
  const { app } = await resetFixture({ audit: (entry) => events.push(entry), sendPasswordReset: ({ token }) => {
    failedToken = token;
    throw new Error('sensitive transport detail');
  } });
  const known = await sendReset(app, resetRequestPath, { username: credentials.username }, 202);
  const unknown = await sendReset(app, resetRequestPath, { username: 'unknown' }, 202);
  assert.deepEqual(known.body, unknown.body);
  await sendReset(app, resetPath, { token: failedToken, password: credentials.password }, 400);
  assert.ok(events.some(({ event }) => event === 'password_reset_delivery_failed'));
  assert.ok(!JSON.stringify(events).includes('sensitive transport detail'));
  assert.ok(!JSON.stringify(events).includes(failedToken));
});

test('an older delivery failure never removes a newly issued reset token', async () => {
  let rejectFirst;
  let deliveredFirst;
  const firstDelivered = new Promise((resolve) => { deliveredFirst = resolve; });
  const deliveries = [];
  const { app } = await resetFixture({ sendPasswordReset: (entry) => {
    deliveries.push(entry);
    if (deliveries.length === 1) {
      deliveredFirst();
      return new Promise((resolve, reject) => { rejectFirst = reject; });
    }
  } });
  const firstRequest = sendReset(app, resetRequestPath, { username: credentials.username }, 202);
  await firstDelivered;
  await sendReset(app, resetRequestPath, { username: credentials.username }, 202);
  rejectFirst(new Error('transport unavailable'));
  await firstRequest;
  await sendReset(app, resetPath, { token: deliveries[0].token, password: credentials.password }, 400);
  await sendReset(app, resetPath, { token: deliveries[1].token, password: credentials.password }, 204);
});

test('password reset cannot be bypassed by a login paused during session regeneration or saving', async () => {
  for (const operation of ['regenerate', 'set']) {
    const { app, store, issue } = await resetFixture();
    const token = await issue();
    const context = await csrf(app);
    const original = store[operation].bind(store);
    let release;
    let reached;
    const paused = new Promise((resolve) => { reached = resolve; });
    store[operation] = (...args) => {
      const callback = args.pop();
      if (operation === 'set' && !args[1].userId) return original(...args, callback);
      return original(...args, (error) => {
        release = () => callback(error);
        reached();
      });
    };
    const pending = request(app).post('/login').set('Cookie', context.cookie)
      .set('X-CSRF-Token', context.token).send(credentials).expect(401).then((response) => response);
    await paused;
    await sendReset(app, resetPath, { token, password: randomBytes(24).toString('hex') }, 204);
    store[operation] = original;
    release();
    const response = await pending;
    assert.deepEqual(response.body, unauthorized);
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      for (const cookie of cookies) await request(app).get('/me').set('Cookie', cookie.split(';')[0]).expect(401);
    }
  }
});


test('legacy reset aliases share tokens, single-use redemption and audit events with canonical routes', async () => {
  const events = [];
  const { app, deliveries, issue } = await resetFixture({ audit: (event) => events.push(event) });
  const password = randomBytes(24).toString('hex');
  const old = await issue();
  await sendReset(app, '/password-reset/request', { username: credentials.username }, 202);
  const token = deliveries.at(-1).token;
  await sendReset(app, resetPath, { token: old, password }, 400);
  const confirmed = await sendReset(app, resetPath, { token, password }, 204);
  assert.equal(confirmed.headers['cache-control'], 'no-store');
  await sendReset(app, '/password-reset/reset', { token, password }, 400);
  const current = await issue();
  await sendReset(app, '/password-reset/reset', { token: current, password }, 204);
  await sendReset(app, resetPath, { token: current, password }, 400);
  await sendLogin(app, { ...credentials, password }, 200);
  assert.deepEqual(events.filter(({ event }) => event.startsWith('password_reset_')).map(({ event }) => event), [
    'password_reset_requested', 'password_reset_requested', 'password_reset_failure',
    'password_reset_success', 'password_reset_failure', 'password_reset_requested',
    'password_reset_success', 'password_reset_failure',
  ]);
});

test('canonical and legacy reset routes share rate limits before CSRF and parsing', async () => {
  const events = [];
  const { app } = await resetFixture({ resetLimit: { limit: 2 }, audit: (event) => events.push(event) });
  await request(app).post('/password-reset/request').expect(403);
  await request(app).post('/reset/confirm').set('Content-Type', 'application/json').send('{').expect(400);
  for (const path of ['/reset/request', '/password-reset/reset']) {
    const response = await request(app).post(path).expect(429);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.ok(response.headers.ratelimit);
  }
  assert.equal(events.filter(({ event }) => event === 'password_reset_rate_limited').length, 2);
});


test('reset routes reject unencrypted requests and audit case and trailing-slash aliases', async () => {
  const events = [];
  const { app, deliveries } = await resetFixture({ audit: (event) => events.push(event) });
  for (const path of ['/reset/request', '/reset/confirm']) {
    const response = await supertest(app).post(path).set('X-Forwarded-Proto', 'https')
      .send({ username: credentials.username }).expect(400);
    assert.deepEqual(response.body, { error: 'HTTPS required' });
    assert.equal(response.headers['set-cookie'], undefined);
  }
  for (const path of ['/RESET/REQUEST/', '/RESET/CONFIRM/']) {
    await request(app).post(path).expect(403);
  }
  await sendReset(app, '/RESET/REQUEST/', { username: credentials.username }, 202);
  await sendReset(app, '/RESET/CONFIRM/', {
    token: deliveries[0].token, password: randomBytes(24).toString('hex'),
  }, 204);
  assert.deepEqual(events.map(({ event }) => event), [
    'password_reset_request_failure', 'password_reset_failure',
    'password_reset_request_failure', 'password_reset_failure',
    'password_reset_requested', 'password_reset_success',
  ]);
});

async function passwordChangeFixture(options = {}) {
  const events = [];
  const setup = await fixture({ audit: (entry) => events.push(entry), ...options });
  const cookie = cookieOf(await login(setup.app));
  const context = await csrf(setup.app, cookie);
  const change = (body, { id = '1', token = context.token, sessionCookie = cookie } = {}) => {
    let req = request(setup.app).post(`/api/users/${id}/password`).set('Content-Type', 'application/json');
    if (sessionCookie) req = req.set('Cookie', sessionCookie);
    if (token) req = req.set('X-CSRF-Token', token);
    return req.send(body);
  };
  return { ...setup, events, cookie, context, change };
}
const newPassword = () => ` ${randomBytes(24).toString('hex')} `;

test('password change replaces the salted hash, rotates the session and revokes other sessions', async () => {
  const { app, users, cookie, context, change } = await passwordChangeFixture();
  const otherCookie = cookieOf(await login(app));
  const before = { ...users.get('1') };
  const password = newPassword();
  const response = await change({ currentPassword: credentials.password, newPassword: password }).expect(204);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.text, '');
  const rotated = cookieOf(response);
  assert.notEqual(rotated, cookie);
  const record = users.get('1');
  assert.ok(Buffer.isBuffer(record.salt) && record.salt.length === 16);
  assert.ok(Buffer.isBuffer(record.passwordHash) && record.passwordHash.length === 64);
  assert.ok(!record.salt.equals(before.salt));
  assert.ok(!record.passwordHash.equals(before.passwordHash));
  assert.ok(!JSON.stringify(record).includes(password.trim()));
  await request(app).get('/me').set('Cookie', cookie).expect(401);
  await request(app).get('/me').set('Cookie', otherCookie).expect(401);
  const me = await request(app).get('/me').set('Cookie', rotated).expect(200);
  assert.deepEqual(me.body, { id: '1', username: credentials.username });
  // The previous CSRF token is not carried into the rotated session.
  await change({ currentPassword: password, newPassword: newPassword() },
    { sessionCookie: rotated, token: context.token }).expect(403);
  await sendLogin(app, credentials, 401);
  await sendLogin(app, { ...credentials, password: password.trim() }, 401);
  await sendLogin(app, { ...credentials, password }, 200);
});

test('password change rejects unauthenticated, revoked and other-user sessions', async () => {
  const { app, users, cookie, change } = await passwordChangeFixture();
  const body = { currentPassword: credentials.password, newPassword: newPassword() };
  const before = { ...users.get('1') };
  const anonymous = await change(body, { sessionCookie: null, token: null }).expect(401);
  assert.deepEqual(anonymous.body, unauthorized);
  assert.equal(anonymous.headers['cache-control'], 'no-store');
  const anonymousContext = await csrf(app);
  const withToken = await change(body, { sessionCookie: anonymousContext.cookie, token: anonymousContext.token }).expect(401);
  assert.deepEqual(withToken.body, unauthorized);
  assertCleared(withToken);
  const other = await createUsers('other', credentials.password);
  users.set('2', { ...other.get('1'), id: '2' });
  const otherBefore = { ...users.get('2') };
  for (const id of ['2', '999']) {
    const forbidden = await change(body, { id }).expect(403);
    assert.deepEqual(forbidden.body, { error: 'Forbidden' });
    assert.equal(forbidden.headers['cache-control'], 'no-store');
  }
  assert.deepEqual(users.get('2'), otherBefore);
  assert.deepEqual(users.get('1'), before);
  users.get('1').credentialVersion = 'revoked';
  const revoked = await change(body).expect(401);
  assert.deepEqual(revoked.body, unauthorized);
  await request(app).get('/me').set('Cookie', cookie).expect(401);
});

test('password change requires session-bound CSRF and the correct current password', async () => {
  const { app, users, cookie, change } = await passwordChangeFixture();
  const body = { currentPassword: credentials.password, newPassword: newPassword() };
  const before = { ...users.get('1') };
  const anonymousContext = await csrf(app);
  for (const token of [null, 'not-a-token', 'a'.repeat(64), anonymousContext.token]) {
    const response = await change(body, { token }).expect(403);
    assert.deepEqual(response.body, { error: 'Forbidden' });
    assert.equal(response.headers['cache-control'], 'no-store');
  }
  for (const currentPassword of ['wrong password', credentials.password.trim()]) {
    const response = await change({ ...body, currentPassword }).expect(401);
    assert.deepEqual(response.body, unauthorized);
    assert.equal(response.headers['cache-control'], 'no-store');
  }
  assert.deepEqual(users.get('1'), before);
  await request(app).get('/me').set('Cookie', cookie).expect(200);
  await sendLogin(app, credentials, 200);
});

test('password change strictly validates the body without trimming', async () => {
  const { app, users, change } = await passwordChangeFixture({ passwordChangeLimit: { limit: 100 } });
  const before = { ...users.get('1') };
  const currentPassword = credentials.password;
  for (const body of [{}, { currentPassword }, { newPassword: newPassword() },
    { currentPassword, newPassword: 'x'.repeat(11) }, { currentPassword, newPassword: 'x'.repeat(1025) },
    { currentPassword: '', newPassword: newPassword() }, { currentPassword: 'x'.repeat(1025), newPassword: newPassword() },
    { currentPassword, newPassword: 123456789012 }, { currentPassword, newPassword: newPassword(), extra: true },
    [currentPassword, newPassword()], '{']) {
    const response = await change(body).expect(400);
    assert.deepEqual(response.body, { error: 'Bad request' });
    assert.equal(response.headers['cache-control'], 'no-store');
  }
  assert.deepEqual(users.get('1'), before);
  // Twelve characters including surrounding whitespace is accepted and preserved.
  const spaced = '  1234567890';
  await change({ currentPassword, newPassword: spaced }).expect(204);
  await sendLogin(app, { ...credentials, password: '1234567890' }, 401);
  await sendLogin(app, { ...credentials, password: spaced }, 200);
});

test('password change audits outcomes as event/timestamp only and is rate limited', async () => {
  const { app, events, cookie, change } = await passwordChangeFixture({ passwordChangeLimit: { limit: 4 } });
  const password = newPassword();
  await change({ currentPassword: 'wrong password', newPassword: password }).expect(401);
  await change({ currentPassword: credentials.password, newPassword: password }, { token: null }).expect(403);
  await change({ currentPassword: credentials.password }).expect(400);
  await change({ currentPassword: credentials.password, newPassword: password }).expect(204);
  const limited = await change({ currentPassword: password, newPassword: newPassword() }).expect(429);
  assert.deepEqual(limited.body, { error: 'Too many requests' });
  assert.equal(limited.headers['cache-control'], 'no-store');
  assert.ok(limited.headers.ratelimit);
  assert.ok(limited.headers['retry-after']);
  await sendLogin(app, { ...credentials, password }, 200);
  const changeEvents = events.filter(({ event }) => event.startsWith('password_change'));
  assert.deepEqual(changeEvents.map(({ event }) => event), ['password_change_failure', 'password_change_failure',
    'password_change_failure', 'password_change_success', 'password_change_rate_limited']);
  for (const entry of events) {
    assert.deepEqual(Object.keys(entry).sort(), ['event', 'timestamp']);
    assert.ok(Number.isFinite(Date.parse(entry.timestamp)));
  }
  const output = JSON.stringify(events);
  for (const sensitive of [credentials.username, credentials.password, password, cookie]) {
    assert.ok(!output.includes(sensitive));
  }
});

test('password change session failures return generic 500 and clear the cookie', async () => {
  const { store, events, change } = await passwordChangeFixture();
  store.destroy = (id, callback) => callback(new Error('sensitive backend detail'));
  const response = await change({ currentPassword: credentials.password, newPassword: newPassword() }).expect(500);
  assert.deepEqual(response.body, internalError);
  assert.equal(response.headers['cache-control'], 'no-store');
  assertCleared(response);
  assert.deepEqual(events.slice(-2).map(({ event }) => event), ['session_error', 'password_change_failure']);
});

test('password change requires HTTPS', async () => {
  const { app } = await fixture();
  const insecure = await supertest(app).post('/api/users/1/password').send({}).expect(400);
  assert.deepEqual(insecure.body, { error: 'HTTPS required' });
});
