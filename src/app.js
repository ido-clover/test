import express from 'express';
import session from 'express-session';
import { rateLimit } from 'express-rate-limit';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { z } from 'zod';
import { createSeedUsers, hashPassword, validCredentials } from './seed.js';
import packageInfo from '../package.json' with { type: 'json' };

export { createUsers } from './seed.js';

const SESSION_LIFETIME = 60 * 60 * 1000;
const RESET_LIFETIME = 15 * 60 * 1000;
const RESET_REQUEST_PATHS = ['/reset/request', '/password-reset/request'];
const EMAIL_RESET_PATH = '/api/password-reset';
const RESET_CONFIRM_PATHS = ['/reset/confirm', '/password-reset/reset', '/api/password-reset/confirm'];
const EXPORT_SECRET_FIELDS = ['salt', 'passwordHash', 'credentialVersion'];
const tokenHash = (token) => createHash('sha256').update(token).digest('hex');
const PASSWORD_CHANGE_PATH = '/api/users/:id/password';
// Bounds match login; passwords are never trimmed or normalized.
const passwordChangeSchema = z.strictObject({
  currentPassword: z.string().min(1).max(1024),
  newPassword: z.string().min(12).max(1024),
});

export async function createApp({ env = process.env, store = new session.MemoryStore(), users, loginLimit = {}, resetLimit = {}, passwordChangeLimit = {}, sendPasswordReset, logResetLink = (link) => console.info(link), now = Date.now, audit = (entry) => console.info(JSON.stringify(entry)) } = {}) {
  const production = env.NODE_ENV === 'production';
  if (production && (typeof env.SESSION_SECRET !== 'string' || !env.SESSION_SECRET.trim())) {
    throw new Error('SESSION_SECRET is required in production');
  }
  const app = express();
  app.disable('x-powered-by');
  const emit = (event) => {
    try { audit({ event, timestamp: new Date().toISOString() }); } catch { /* Never expose logger failures. */ }
  };
  app.use((req, res, next) => {
    if (req.method === 'POST' && /^\/login\/?$/i.test(req.path)) {
      res.once('finish', () => emit(res.statusCode < 400 ? 'login_success'
        : res.statusCode === 429 ? 'login_rate_limited' : 'login_failure'));
    }
    const resetRoute = req.method === 'POST'
      && /^(?:\/reset\/(request|confirm)|\/password-reset\/(request|reset)|\/api\/password-reset(?:\/confirm)?)\/?$/i.test(req.path);
    if (resetRoute) {
      const operation = /\/(?:confirm|reset)\/?$/i.test(req.path) ? 'reset' : 'request';
      res.once('finish', () => emit(res.statusCode === 429 ? 'password_reset_rate_limited'
        : operation === 'request' ? (res.statusCode < 400 ? 'password_reset_requested' : 'password_reset_request_failure')
          : (res.statusCode < 400 ? 'password_reset_success' : 'password_reset_failure')));
    }
    // Require encryption on the actual connection, regardless of forwarded headers.
    if (!req.socket.encrypted) return res.status(400).json({ error: 'HTTPS required' });
    res.set('Strict-Transport-Security', 'max-age=31536000');
    return next();
  });
  app.get('/health', (req, res) => res.type('text').send('ok'));
  app.get('/version', (req, res) => res.json({ version: packageInfo.version }));
  if (env.TRUST_PROXY_HOPS !== undefined) {
    if (!/^[1-9]\d*$/.test(env.TRUST_PROXY_HOPS)
      || !Number.isSafeInteger(Number(env.TRUST_PROXY_HOPS))) {
      throw new Error('TRUST_PROXY_HOPS must be a positive integer');
    }
    app.set('trust proxy', Number(env.TRUST_PROXY_HOPS));
  }
  const userStore = users ?? await createSeedUsers(env);
  const resetTokens = new Map();
  const authenticatedUser = (req) => {
    const user = userStore.get(req.session.userId);
    return user && user.credentialVersion === req.session.credentialVersion ? user : undefined;
  };
  const dummySalt = randomBytes(16);
  const dummyHash = await hashPassword(randomBytes(32), dummySalt);
  const cookieOptions = { httpOnly: true, sameSite: 'lax', secure: true, path: '/' };
  const clearCookie = (res) => res.clearCookie('sid', cookieOptions);
  const unauthorized = (res) => res.status(401).json({ error: 'Unauthorized' });
  const passwordMatches = async (password, salt, expectedHash) => {
    const passwordHash = await hashPassword(password, salt);
    return Buffer.isBuffer(expectedHash) && expectedHash.length === passwordHash.length
      && timingSafeEqual(passwordHash, expectedHash);
  };

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => {
      return res.status(429).json({ error: 'Too many requests' });
    },
    ...loginLimit,
  });
  app.post('/login', loginLimiter);
  const resetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ error: 'Too many requests' }),
    ...resetLimit,
  });
  app.post([...RESET_REQUEST_PATHS, EMAIL_RESET_PATH, ...RESET_CONFIRM_PATHS], (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    return resetLimiter(req, res, next);
  });
  const passwordChangeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ error: 'Too many requests' }),
    ...passwordChangeLimit,
  });
  app.post(PASSWORD_CHANGE_PATH, (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.once('finish', () => emit(res.statusCode === 429 ? 'password_change_rate_limited'
      : res.statusCode < 400 ? 'password_change_success' : 'password_change_failure'));
    return passwordChangeLimiter(req, res, next);
  });
  app.use(express.json({ limit: '16kb' }));
  app.use(express.urlencoded({ extended: false, limit: '16kb', parameterLimit: 3 }));
  app.use(session({
    name: 'sid',
    secret: [env.SESSION_SECRET?.trim() ? env.SESSION_SECRET : randomBytes(32).toString('hex'),
      ...(env.SESSION_SECRET_PREVIOUS?.trim() ? [env.SESSION_SECRET_PREVIOUS] : [])],
    store,
    resave: false,
    saveUninitialized: false,
    cookie: { ...cookieOptions, maxAge: SESSION_LIFETIME },
  }));

  const csrfToken = (req) => req.session.csrfToken ??= randomBytes(32).toString('hex');
  const requireCsrf = (req, res, next) => {
    const supplied = req.get('X-CSRF-Token') ?? req.body?._csrf;
    const expected = req.session.csrfToken;
    if (typeof supplied !== 'string' || !/^[a-f0-9]{64}$/.test(supplied)
      || typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)
      || !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };
  app.get('/csrf-token', (req, res) => {
    res.set('Cache-Control', 'no-store');
    return res.json({ csrfToken: csrfToken(req) });
  });
  app.get('/login', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.set('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    return res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Log in</title></head><body>
<h1>Log in</h1><form method="post" action="/login">
<input type="hidden" name="_csrf" value="${csrfToken(req)}">
<label>Username <input name="username" required maxlength="128" autocomplete="username"></label>
<label>Password <input name="password" type="password" required maxlength="1024" autocomplete="current-password"></label>
<button type="submit">Log in</button></form></body></html>`);
  });

  app.post('/login', requireCsrf, async (req, res, next) => {
    const credentials = { ...req.body };
    delete credentials._csrf;
    if (!validCredentials(credentials)) {
      return res.status(400).json({ error: 'Bad request' });
    }
    try {
      const user = [...userStore.values()].find((entry) => entry.username === credentials.username);
      const expectedHash = user?.passwordHash ?? dummyHash;
      const credentialVersion = user?.credentialVersion;
      const matches = await passwordMatches(credentials.password, user?.salt ?? dummySalt, expectedHash);
      if (!user || !matches || user.passwordHash !== expectedHash) {
        return unauthorized(res);
      }
      await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
      if (user.passwordHash !== expectedHash) return unauthorized(res);
      req.session.userId = user.id;
      if (credentialVersion !== undefined) req.session.credentialVersion = credentialVersion;
      csrfToken(req);
      await new Promise((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
      if (user.passwordHash !== expectedHash) {
        await new Promise((resolve, reject) => req.session.destroy((error) => error ? reject(error) : resolve()));
        clearCookie(res);
        return unauthorized(res);
      }
      user.lastLogin = new Date(now()).toISOString();
      res.set('Cache-Control', 'no-store');
      if (req.is('application/x-www-form-urlencoded')) return res.redirect(303, '/account');
      return res.json({ id: user.id, username: user.username });
    } catch (error) {
      return next(error);
    }
  });

  const requestReset = (field, deliver) => async (req, res) => {
    const payload = { ...req.body };
    delete payload._csrf;
    if (Object.keys(payload).length !== 1 || typeof payload[field] !== 'string'
      || payload[field].length < 1 || payload[field].length > (field === 'email' ? 254 : 128)
      || (field === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email))) {
      return res.status(400).json({ error: 'Bad request' });
    }
    if (typeof deliver !== 'function') {
      return res.status(503).json({ error: 'Service unavailable' });
    }
    // Keep at most one token per user, and discard expired records on requests.
    for (const [id, entry] of resetTokens) {
      if (entry.expiresAt <= now()) resetTokens.delete(id);
    }
    const user = [...userStore.values()].find((entry) => entry[field] === payload[field]);
    if (user) {
      const token = randomBytes(32).toString('hex');
      const entry = { hash: tokenHash(token), expiresAt: now() + RESET_LIFETIME,
        passwordHash: user.passwordHash };
      resetTokens.set(user.id, entry);
      try {
        // Delivery uses the matched trusted record, never a request-supplied destination.
        await deliver({ user: { id: user.id, username: user.username }, token,
          expiresAt: new Date(entry.expiresAt).toISOString() });
      } catch {
        if (resetTokens.get(user.id) === entry) resetTokens.delete(user.id);
        emit('password_reset_delivery_failed');
      }
    }
    return res.status(202).json({ message: 'If the account exists, reset instructions will be sent.' });
  };
  app.post(RESET_REQUEST_PATHS, requireCsrf, requestReset('username', sendPasswordReset));
  app.post(EMAIL_RESET_PATH, requireCsrf, requestReset('email', ({ token }) =>
    logResetLink(`/api/password-reset/confirm?token=${token}`)));

  app.post(RESET_CONFIRM_PATHS, requireCsrf, async (req, res, next) => {
    const payload = { ...req.body };
    delete payload._csrf;
    if (Object.keys(payload).length !== 2 || typeof payload.token !== 'string'
      || !/^[a-f0-9]{64}$/.test(payload.token) || typeof payload.password !== 'string'
      || payload.password.length < 1 || payload.password.length > 1024) {
      return res.status(400).json({ error: 'Bad request' });
    }
    const invalidToken = () => res.status(400).json({ error: 'Invalid or expired reset token' });
    const hash = tokenHash(payload.token);
    const found = [...resetTokens].find(([, entry]) => entry.hash === hash);
    if (!found) return invalidToken();
    const [id, entry] = found;
    const user = userStore.get(id);
    if (!user || entry.expiresAt <= now() || user.passwordHash !== entry.passwordHash) {
      resetTokens.delete(id);
      return invalidToken();
    }
    try {
      const salt = randomBytes(16);
      const passwordHash = await hashPassword(payload.password, salt);
      // No await between this check, consuming the token and changing credentials.
      if (resetTokens.get(id) !== entry || entry.expiresAt <= now()
        || userStore.get(id) !== user || user.passwordHash !== entry.passwordHash) return invalidToken();
      resetTokens.delete(id);
      user.salt = salt;
      user.passwordHash = passwordHash;
      user.credentialVersion = randomBytes(32).toString('hex');
      return res.sendStatus(204);
    } catch (error) {
      return next(error);
    }
  });

  app.get(['/admin/users', '/api/admin/users'], (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.once('finish', () => emit(res.statusCode < 400 ? 'admin_users_success' : 'admin_users_denied'));
    const user = authenticatedUser(req);
    if (!user) {
      return req.session.destroy((error) => {
        clearCookie(res);
        if (error) return next(error);
        return unauthorized(res);
      });
    }
    if (user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    return next();
  });
  app.get('/admin/users', (req, res) =>
    res.json([...userStore.values()].map(({ id, username }) => ({ id, username }))));
  app.get('/api/admin/users', (req, res) =>
    res.json([...userStore.values()].map(({ username, email, lastLogin }) =>
      ({ username, email: email ?? null, lastLogin: lastLogin ?? null }))));
  app.delete('/api/admin/users/:id', (req, res, next) => {
    const user = authenticatedUser(req);
    if (!user) {
      return req.session.destroy((error) => {
        clearCookie(res);
        if (error) return next(error);
        return unauthorized(res);
      });
    }
    if (user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    if (!userStore.delete(req.params.id)) return res.status(404).json({ error: 'Not found' });
    return res.sendStatus(204);
  });

  app.get('/api/users/:id/export', (req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    res.once('finish', () => emit(res.statusCode < 400 ? 'user_export_success' : 'user_export_denied'));
    const user = authenticatedUser(req);
    if (!user) {
      return req.session.destroy((error) => {
        clearCookie(res);
        if (error) return next(error);
        return unauthorized(res);
      });
    }
    // Authorize before any lookup so callers cannot probe which ids exist.
    if (user.id !== req.params.id && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const record = userStore.get(req.params.id);
    if (!record) return res.status(404).json({ error: 'Not found' });
    const exported = { ...record };
    for (const field of EXPORT_SECRET_FIELDS) delete exported[field];
    res.attachment(`user-${record.id}.json`);
    return res.type('json').send(JSON.stringify(exported, null, 2));
  });

  app.get('/me', (req, res, next) => {
    const user = authenticatedUser(req);
    if (!user) {
      return req.session.destroy((error) => {
        clearCookie(res);
        if (error) return next(error);
        return unauthorized(res);
      });
    }
    return res.json({ id: user.id, username: user.username });
  });

  app.get('/account', (req, res) => {
    if (!authenticatedUser(req)) return res.redirect(303, '/login');
    res.set('Cache-Control', 'no-store');
    res.set('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    return res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Account</title></head><body>
<h1>Signed in</h1><form method="post" action="/logout">
<input type="hidden" name="_csrf" value="${csrfToken(req)}">
<button type="submit">Log out</button></form></body></html>`);
  });

  app.post('/api/profile/avatar', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!authenticatedUser(req)) return unauthorized(res);
    return requireCsrf(req, res, next);
  }, async (req, res, next) => {
    const user = authenticatedUser(req);
    const payload = { ...req.body };
    delete payload._csrf;
    let url;
    try {
      if (Object.keys(payload).length !== 1 || typeof payload.url !== 'string'
        || payload.url.length > 2048) throw new Error();
      url = new URL(payload.url);
      // Only explicitly trusted origins may receive server-side requests; never follow redirects.
      const allowed = (env.AVATAR_ALLOWED_ORIGINS ?? '').split(',').map((origin) => origin.trim());
      if (url.protocol !== 'https:' || url.username || url.password
        || !allowed.includes(url.origin) || typeof user.username !== 'string'
        || !/^[^/\\\0]{1,128}$/.test(user.username)) throw new Error();
    } catch {
      return res.status(400).json({ error: 'Bad request' });
    }
    let image;
    try {
      const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!response.ok || !/^image\//i.test(response.headers.get('content-type') ?? '')
        || !response.body) throw new Error();
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) throw new Error();
        chunks.push(chunk);
      }
      if (!size) throw new Error();
      image = Buffer.concat(chunks);
    } catch {
      return res.status(502).json({ error: 'Image download failed' });
    }
    try {
      const path = `./uploads/${user.username}.png`;
      await mkdir('./uploads', { recursive: true });
      await writeFile(path, image, { mode: 0o600 });
      return res.json({ path });
    } catch (error) {
      return next(error);
    }
  });

  app.post(PASSWORD_CHANGE_PATH, (req, res, next) => {
    if (authenticatedUser(req)) return requireCsrf(req, res, next);
    return req.session.destroy((error) => {
      clearCookie(res);
      if (error) return next(error);
      return unauthorized(res);
    });
  }, async (req, res, next) => {
    const user = authenticatedUser(req);
    if (user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
    const payload = { ...req.body };
    delete payload._csrf;
    const parsed = passwordChangeSchema.safeParse(payload);
    if (!parsed.success) return res.status(400).json({ error: 'Bad request' });
    const { currentPassword, newPassword } = parsed.data;
    try {
      const expectedHash = user.passwordHash;
      if (!await passwordMatches(currentPassword, user.salt, expectedHash)) return unauthorized(res);
      const salt = randomBytes(16);
      const passwordHash = await hashPassword(newPassword, salt);
      // No await between this check and changing credentials; concurrent changes win.
      if (userStore.get(user.id) !== user || user.passwordHash !== expectedHash) return unauthorized(res);
      const credentialVersion = randomBytes(32).toString('hex');
      user.salt = salt;
      user.passwordHash = passwordHash;
      // Revokes every existing session, including this one until it is reissued below.
      user.credentialVersion = credentialVersion;
      await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
      req.session.userId = user.id;
      req.session.credentialVersion = credentialVersion;
      csrfToken(req);
      await new Promise((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
      return res.sendStatus(204);
    } catch (error) {
      return next(error);
    }
  });

  app.post('/logout', (req, res, next) => {
    // An absent authenticated session has no state for an attacker to change.
    if (!req.session.userId) return next();
    return requireCsrf(req, res, next);
  }, (req, res, next) => {
    req.session.destroy((error) => {
      clearCookie(res);
      if (error) return next(error);
      emit('logout');
      if (req.is('application/x-www-form-urlencoded')) return res.redirect(303, '/login');
      return res.sendStatus(204);
    });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.type === 'entity.parse.failed' || error.type === 'entity.too.large'
      || error.type === 'parameters.too.many' || error.type === 'charset.unsupported' || error.type === 'encoding.unsupported') {
      return res.status(400).json({ error: 'Bad request' });
    }
    // Prevent express-session from retrying a failed save at response completion.
    req.session = null;
    emit('session_error');
    clearCookie(res);
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
