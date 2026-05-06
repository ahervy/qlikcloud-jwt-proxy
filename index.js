import 'dotenv/config';

import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import { parse as parseCookie } from 'cookie';
import RedisStore from 'connect-redis';
import { createClient } from 'redis';
import compression from 'compression';
import { generators } from 'openid-client';
import jsonwebtoken from 'jsonwebtoken';
import WebSocket, { WebSocketServer } from 'ws';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const env = process.env;

const port = Number(env.PORT || 3000);
const appBaseUrl = removeTrailingSlash(env.APP_BASE_URL || env.frontendUri || `http://localhost:${port}`);
const qlikWebId = env.webIntegrationId;
const idpScope = env.idpScope || 'openid email profile';

const qlikConfig = {
  tenantUri: normalizeTenantHost(env.tenantUri),
  privateKey: normalizePrivateKey(env.privateKey),
  keyId: env.keyId,
  issuer: env.issuer,
};

const authConfig = {
  clientId: env.clientId,
  clientSecret: env.clientSecret,
  redirectUri: env.redirectUri || `${appBaseUrl}/login/callback`,
  idpAuthorizeUri: `${removeTrailingSlash(env.idpUri || '')}/authorize`,
  idpTokenUri: `${removeTrailingSlash(env.idpUri || '')}/oauth/token`,
};

validateConfig();

// This example maps OAuth state values to PKCE code verifiers during login.
const tokenStore = {};

const redisClient = createClient(buildRedisOptions());
redisClient.on('error', (err) => {
  console.error('Redis error:', err);
});

await redisClient.connect();
const store = new RedisStore({ client: redisClient });

const app = express();
app.use(compression({ threshold: 0 }));

app.use(session({
  store,
  secret: env.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    secure: parseBoolean(env.COOKIE_SECURE, appBaseUrl.startsWith('https://')),
    httpOnly: true,
    maxAge: Number(env.SESSION_MAX_AGE_MS || 1000 * 60 * 10),
  },
}));

app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

app.get('/app-config.js', (req, res) => {
  res.type('application/javascript').send(`window.__APP_CONFIG__ = ${JSON.stringify(buildFrontendConfig())};`);
});

app.get('/session', (req, res) => {
  res.json({ authenticated: Boolean(req.session?.qlikSession) });
});

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = generators.codeVerifier(43);
  const codeChallenge = generators.codeChallenge(codeVerifier);

  tokenStore[state] = { codeVerifier };
  res.redirect(buildAuthorizeUrl({ state, codeChallenge, prompt: 'none' }));
});

app.get('/login/callback', async (req, res) => {
  try {
    const { code, error, state } = req.query;

    if (error === 'login_required' || error === 'interaction_required') {
      const state2 = crypto.randomBytes(16).toString('hex');
      const codeVerifier = generators.codeVerifier(43);
      const codeChallenge = generators.codeChallenge(codeVerifier);

      tokenStore[state2] = { codeVerifier };
      res.redirect(buildAuthorizeUrl({ state: state2, codeChallenge }));
      return;
    }

    if (!state || !tokenStore[state]) {
      res.status(401).send('Invalid or expired login state.');
      return;
    }

    const idpTokenRes = await fetch(authConfig.idpTokenUri, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        code_verifier: tokenStore[state].codeVerifier,
        grant_type: 'authorization_code',
        redirect_uri: authConfig.redirectUri,
        client_id: authConfig.clientId,
        client_secret: authConfig.clientSecret,
      }),
    });

    delete tokenStore[state];

    if (!idpTokenRes.ok) {
      console.error(await idpTokenRes.text());
      res.status(502).send('The identity provider token exchange failed.');
      return;
    }

    const idpToken = await idpTokenRes.json();
    const idToken = jsonwebtoken.decode(idpToken.id_token);

    if (!idToken?.email || !idToken?.sub) {
      res.status(502).send('The identity provider did not return the required user claims.');
      return;
    }

    const qlikJwt = createToken(idToken.email, idToken.name || idToken.email, idToken.sub, qlikConfig);
    const qlikSession = await getQlikSessionCookie(qlikConfig.tenantUri, qlikJwt);

    req.session.idToken = idpToken.id_token;
    req.session.qlikSession = encodeURIComponent(qlikSession);

    res.redirect(appBaseUrl);
  } catch (err) {
    console.error(err);
    res.status(500).send('Login callback failed.');
  }
});

app.get('/single/*', async (req, res) => {
  const qlikCookie = getQlikCookieFromSession(req.session);
  if (!qlikCookie) {
    sendNoSession(res);
    return;
  }

  const csrfToken = getCsrfToken(qlikCookie);
  if (!csrfToken) {
    res.status(401).send('Qlik session is missing a CSRF token.');
    return;
  }

  const upstreamUrl = buildQlikUrl(req.originalUrl, {
    'qlik-csrf-token': csrfToken,
    'qlik-web-integration-id': qlikWebId,
  });

  const upstream = await fetch(upstreamUrl, {
    headers: {
      cookie: qlikCookie,
    },
  });

  setCors(res);
  res.set('content-type', upstream.headers.get('content-type') || 'text/html; charset=UTF-8');
  res.status(upstream.status);
  res.end(Buffer.from(await upstream.arrayBuffer()), 'binary');
});

app.get('/api/v1/*', async (req, res) => {
  const qlikCookie = getQlikCookieFromSession(req.session);
  const headers = qlikCookie ? { cookie: qlikCookie } : {};
  const upstream = await fetch(`https://${qlikConfig.tenantUri}${req.originalUrl}`, { headers });

  setCors(res);
  res.status(upstream.status);
  res.end(Buffer.from(await upstream.arrayBuffer()), 'binary');
});

app.get('/resources/*', async (req, res) => {
  setCors(res);
  res.redirect(`https://${qlikConfig.tenantUri}${req.originalUrl}`);
});

app.get('/assets/*', async (req, res) => {
  setCors(res);
  res.redirect(`https://${qlikConfig.tenantUri}${req.originalUrl}`);
});

app.options('/*', async (req, res) => {
  setCors(res);
  res.status(200).end();
});

const server = app.listen(port, () => {
  console.log(`Qlik JWT proxy running at ${appBaseUrl}`);
});

const wss = new WebSocketServer({ server });

wss.on('connection', async (ws, req) => {
  try {
    const qlikCookie = await getQlikCookieFromSocket(req);
    const csrfToken = getCsrfToken(qlikCookie);
    const appId = req.url?.match(/^\/app\/([^?]+)/)?.[1];

    if (!qlikCookie || !csrfToken || !appId) {
      ws.close(1008, 'Missing Qlik session.');
      return;
    }

    let isOpened = false;
    const qlikWebSocket = new WebSocket(`wss://${qlikConfig.tenantUri}/app/${appId}?qlik-csrf-token=${csrfToken}`, {
      headers: {
        cookie: qlikCookie,
      },
    });

    qlikWebSocket.on('error', (err) => {
      console.error(err);
      ws.close(1011, 'Qlik websocket failed.');
    });

    const openPromise = new Promise((resolve) => {
      qlikWebSocket.on('open', resolve);
    });

    ws.on('message', async (data) => {
      if (!isOpened) {
        await openPromise;
        isOpened = true;
      }
      qlikWebSocket.send(data.toString());
    });

    ws.on('close', () => {
      qlikWebSocket.close();
    });

    qlikWebSocket.on('message', (data) => {
      ws.send(data.toString());
    });
  } catch (err) {
    console.error(err);
    ws.close(1011, 'Proxy websocket failed.');
  }
});

function buildAuthorizeUrl({ state, codeChallenge, prompt }) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: authConfig.clientId,
    redirect_uri: authConfig.redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    scope: idpScope,
    state,
  });

  if (prompt) {
    params.set('prompt', prompt);
  }

  return `${authConfig.idpAuthorizeUri}?${params.toString()}`;
}

function buildFrontendConfig() {
  return {
    appId: env.APP_ID || '<APP_ID>',
    sheetId: env.SHEET_ID || '<SHEET_ID>',
    iframeAppId: env.IFRAME_APP_ID || env.APP_ID || '<APP_ID>',
    iframeSheetId: env.IFRAME_SHEET_ID || '<SHEET_ID>',
    embedAppId: env.EMBED_APP_ID || env.APP_ID || '<APP_ID>',
    embedObjectId: env.EMBED_OBJECT_ID || '<OBJECT_ID>',
    theme: env.QLIK_THEME || 'breeze',
  };
}

function buildQlikUrl(path, params) {
  const url = new URL(`https://${qlikConfig.tenantUri}${path}`);
  Object.entries(params).forEach(([key, value]) => {
    if (value) {
      url.searchParams.set(key, value);
    }
  });
  return url;
}

function buildRedisOptions() {
  if (env.REDIS_URL) {
    return { url: env.REDIS_URL };
  }

  const options = {
    socket: {
      host: env.redis_db || 'localhost',
      port: Number(env.redis_port || 6379),
    },
  };

  if (env.redis_pwd) {
    options.password = env.redis_pwd;
  }

  return options;
}

function createToken(email, name, sub, config) {
  const signingOptions = {
    keyid: config.keyId,
    algorithm: 'RS256',
    issuer: config.issuer,
    expiresIn: '1m',
    audience: 'qlik.api/login/jwt-session',
    notBefore: '0s',
  };

  const payload = {
    jti: crypto.randomBytes(16).toString('hex'),
    sub: `BackendApp|${sub}`,
    subType: 'user',
    email_verified: true,
    email,
    name,
  };

  return jsonwebtoken.sign(payload, config.privateKey, signingOptions);
}

async function getQlikSessionCookie(tenantUri, token) {
  const resp = await fetch(`https://${tenantUri}/login/jwt-session`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!resp.ok) {
    throw new Error(`Qlik JWT session request failed with status ${resp.status}: ${await resp.text()}`);
  }

  const setCookieHeaders = getSetCookieHeaders(resp.headers);
  if (!setCookieHeaders.length) {
    throw new Error('Qlik JWT session response did not include a set-cookie header.');
  }

  return setCookieHeaders
    .map((value) => value.split(';')[0])
    .join(';');
}

function getSetCookieHeaders(headers) {
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie();
  }

  return splitCombinedSetCookieHeader(headers.get('set-cookie'));
}

function splitCombinedSetCookieHeader(value) {
  return value ? value.split(/,(?=\s*[^;,]+=)/) : [];
}

function getQlikCookieFromSession(sessionData) {
  return sessionData?.qlikSession ? decodeURIComponent(sessionData.qlikSession) : '';
}

async function getQlikCookieFromSocket(req) {
  const cookieString = req.headers.cookie;
  if (!cookieString) {
    return '';
  }

  const appCookie = parseCookie(cookieString)['connect.sid'];
  if (!appCookie) {
    return '';
  }

  const sidParsed = cookieParser.signedCookie(appCookie, env.sessionSecret);
  if (!sidParsed) {
    return '';
  }

  const savedSession = await getSessionFromStore(sidParsed);
  return getQlikCookieFromSession(savedSession);
}

function getSessionFromStore(sessionId) {
  return new Promise((resolve, reject) => {
    store.get(sessionId, (err, sessionData) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(sessionData);
    });
  });
}

function getCsrfToken(cookieString) {
  return parseCookie(cookieString || '')._csrfToken;
}

function sendNoSession(res) {
  setCors(res);
  res.status(401).send('No web application session or Qlik session cookie.');
}

function setCors(res) {
  res.set('Access-Control-Allow-Origin', appBaseUrl);
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, x-proxy-session-id');
  res.set('Access-Control-Allow-Credentials', 'true');
}

function normalizePrivateKey(value) {
  return value?.replaceAll('\\n', '\n');
}

function normalizeTenantHost(value) {
  return removeTrailingSlash(value || '').replace(/^https?:\/\//, '');
}

function removeTrailingSlash(value) {
  return value.replace(/\/$/, '');
}

function parseBoolean(value, fallback) {
  if (value === undefined) {
    return fallback;
  }
  return ['1', 'true', 'yes'].includes(value.toLowerCase());
}

function validateConfig() {
  const required = {
    tenantUri: qlikConfig.tenantUri,
    privateKey: qlikConfig.privateKey,
    keyId: qlikConfig.keyId,
    issuer: qlikConfig.issuer,
    webIntegrationId: qlikWebId,
    sessionSecret: env.sessionSecret,
    clientId: authConfig.clientId,
    clientSecret: authConfig.clientSecret,
    idpUri: env.idpUri,
  };

  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([key]) => key);

  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}
