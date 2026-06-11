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

// Configuration
const port = Number(env.PORT || 3000);
const appBaseUrl = removeTrailingSlash(env.APP_BASE_URL || `http://localhost:${port}`);
const qlikWebId = env.WEB_INTEGRATION_ID;
const idpScope = env.IDP_SCOPE || 'openid email profile';

// Qlik tenant and JWT identity-provider settings. tenantUri accepts either a
// bare host or URL so the rest of the app can always build https:// URLs.
const qlikConfig = {
  tenantUri: normalizeTenantHost(env.TENANT_URI),
  privateKey: env.QLIK_JWT_PRIVATE_KEY?.replaceAll('\\n', '\n'),
  keyId: env.QLIK_JWT_KEY_ID,
  issuer: env.QLIK_JWT_ISSUER,
};

const authConfig = {
  clientId: env.IDP_CLIENT_ID,
  clientSecret: env.IDP_CLIENT_SECRET,
  redirectUri: env.IDP_REDIRECT_URI || `${appBaseUrl}/login/callback`,
  idpAuthorizeUri: `${removeTrailingSlash(env.IDP_URI || '')}/authorize`,
  idpTokenUri: `${removeTrailingSlash(env.IDP_URI || '')}/oauth/token`,
};

validateConfig();

// PKCE verifier stays server-side and is released only after the callback proves
// it owns the matching state value from the authorization redirect.
const tokenStore = {};

// Session Storage
const redisClient = createClient(buildRedisOptions());
redisClient.on('error', (err) => console.error('Redis error:', err));
await redisClient.connect();

// Redis-backed sessions let HTTP requests and websocket upgrades share the same
// Qlik cookie, including when the app is scaled beyond one Node process.
const store = new RedisStore({ client: redisClient });

const app = express();
app.use(compression({ threshold: 0 }));
app.use(session({
  store,
  secret: env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    // The browser should not expose this application session to frontend code;
    // it only identifies the server-side Redis session.
    sameSite: 'lax',
    secure: parseBoolean(env.COOKIE_SECURE, appBaseUrl.startsWith('https://')),
    httpOnly: true,
    maxAge: Number(env.SESSION_MAX_AGE_MS || 1000 * 60 * 10),
  },
}));

// App Routes
app.get('/', (req, res) => res.sendFile(join(__dirname, 'index.html')));

app.get('/app-config.js', (req, res) => {
  // Keep demo IDs out of static frontend code so the same quickstart can be
  // reused with different Qlik apps, sheets, and themes through environment vars.
  res.type('application/javascript').send(`window.__APP_CONFIG__ = ${JSON.stringify({
    appId: env.APP_ID || '<APP_ID>',
    sheetId: env.SHEET_ID || '<SHEET_ID>',
    iframeAppId: env.IFRAME_APP_ID || env.APP_ID || '<APP_ID>',
    iframeSheetId: env.IFRAME_SHEET_ID || '<SHEET_ID>',
    theme: env.QLIK_THEME || 'breeze',
    qlikEmbedAppId: env.QLIK_EMBED_APP_ID || env.APP_ID || '<APP_ID>',
    qlikEmbedObjectId: env.QLIK_EMBED_OBJECT_ID || '<OBJECT_ID>',
  })};`);
});

app.get('/session', (req, res) => {
  // The frontend only needs a yes/no answer. The actual Qlik cookie stays
  // server-side and is never returned to browser JavaScript.
  res.json({ authenticated: Boolean(req.session?.qlikSession) });
});

// Authentication Routes
app.get('/login', (req, res) => startLogin(res, 'none'));

app.get('/login/callback', async (req, res) => {
  try {
    const { code, error, state } = req.query;

    if (error) {
      // prompt=none is a silent SSO probe; IdP errors fall back to interactive
      // login while keeping the same PKCE/state protection.
      startLogin(res);
      return;
    }

    if (!state || !tokenStore[state]) {
      res.status(401).send('Invalid or expired login state.');
      return;
    }

    if (!code) {
      res.status(400).send('Missing authorization code from identity provider.');
      return;
    }

    const idpToken = await exchangeAuthorizationCode(code, state, tokenStore[state].codeVerifier);
    if (!idpToken) {
      res.status(502).send('The identity provider token exchange failed.');
      return;
    }

    const idToken = jsonwebtoken.decode(idpToken.id_token);
    if (!idToken?.email || !idToken?.sub) {
      res.status(502).send('The identity provider did not return the required user claims.');
      return;
    }

    const qlikJwt = createQlikJwt(idToken.email, idToken.name || idToken.email, idToken.sub);
    const qlikSession = await exchangeJwtForQlikCookie(qlikJwt);

    // Store both the original IdP token and the Qlik session for this browser
    // session. Proxied requests use the Qlik cookie, not the IdP token.
    req.session.idToken = idpToken.id_token;
    // The Qlik cookie string contains separators that should survive JSON
    // serialization in Redis until the proxy forwards it upstream.
    req.session.qlikSession = encodeURIComponent(qlikSession);
    res.redirect(appBaseUrl);
  } catch (err) {
    console.error(err);
    res.status(500).send('Login callback failed.');
  }
});

// Qlik HTTP Proxy Routes
app.get('/single/*', async (req, res) => {
  try {
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

    // Qlik requires CSRF and web integration IDs on embedded content URLs even
    // though the session cookie is also forwarded by the proxy.
    const upstreamUrl = new URL(`https://${qlikConfig.tenantUri}${req.originalUrl}`);
    upstreamUrl.searchParams.set('qlik-csrf-token', csrfToken);
    upstreamUrl.searchParams.set('qlik-web-integration-id', qlikWebId);

    const upstream = await fetch(upstreamUrl, { headers: { cookie: qlikCookie } });
    setCors(res);
    res.set('content-type', upstream.headers.get('content-type') || 'text/html; charset=UTF-8');
    await sendUpstream(res, upstream);
  } catch (err) {
    console.error('Proxy /single failed:', err.message);
    res.status(502).send('Failed to load content from Qlik Cloud. Check that tenantUri is correct and reachable.');
  }
});

app.get('/api/v1/*', async (req, res) => {
  try {
    const qlikCookie = getQlikCookieFromSession(req.session);
    // Some Qlik API endpoints are public while others require a Qlik session.
    // Forward the stored Qlik session cookie when it exists. If no session
    // exists, forward the request without a cookie and let Qlik Cloud return the
    // appropriate public response or authorization error.
    const upstream = await fetch(`https://${qlikConfig.tenantUri}${req.originalUrl}`, {
      headers: qlikCookie ? { cookie: qlikCookie } : {},
    });

    setCors(res);
    await sendUpstream(res, upstream);
  } catch (err) {
    console.error('Proxy /api/v1 failed:', err.message);
    res.status(502).send('Failed to reach Qlik Cloud API. Check that tenantUri is correct and reachable.');
  }
});

app.get('/resources/*', (req, res) => proxyPublicAsset(req, res, 'resources'));
app.get('/assets/*', (req, res) => proxyPublicAsset(req, res, 'assets'));

app.options('/*', (req, res) => {
  // Embedded Qlik assets are loaded through this origin, so preflight responses
  // need to allow the browser to include the Express session cookie.
  setCors(res);
  res.status(200).end();
});

const server = app.listen(port, () => {
  console.log(`Qlik JWT proxy running at ${appBaseUrl}`);
  console.log(`  Tenant:   ${qlikConfig.tenantUri}`);
  console.log(`  IdP:      ${authConfig.idpAuthorizeUri}`);
  console.log(`  Callback: ${authConfig.redirectUri}`);
  console.log(`  Redis:    ${env.REDIS_URL || `${env.REDIS_HOST || 'localhost'}:${env.REDIS_PORT || 6379}`}`);
});

// Qlik Websocket Proxy
const wss = new WebSocketServer({ server });

wss.on('connection', async (ws, req) => {
  try {
    const qlikCookie = await getQlikCookieFromSocket(req);
    const csrfToken = getCsrfToken(qlikCookie);
    // Qlik engine websocket URLs include the app id in /app/:appId.
    const appId = req.url?.match(/^\/app\/([^?]+)/)?.[1];

    if (!qlikCookie || !csrfToken || !appId) {
      ws.close(1008, 'Missing Qlik session.');
      return;
    }

    const qlikWebSocket = new WebSocket(`wss://${qlikConfig.tenantUri}/app/${appId}?qlik-csrf-token=${csrfToken}`, {
      headers: { cookie: qlikCookie },
    });

    qlikWebSocket.on('error', (err) => {
      console.error(err);
      ws.close(1011, 'Qlik websocket failed.');
    });

    // Browser messages can arrive before Qlik's websocket opens; wait once so
    // the first engine message is not lost or reordered.
    let isOpened = false;
    const openPromise = new Promise((resolve) => qlikWebSocket.on('open', resolve));

    ws.on('message', async (data) => {
      if (!isOpened) {
        await openPromise;
        isOpened = true;
      }
      qlikWebSocket.send(data.toString());
    });

    ws.on('close', () => qlikWebSocket.close());
    qlikWebSocket.on('message', (data) => ws.send(data.toString()));
  } catch (err) {
    console.error(err);
    ws.close(1011, 'Proxy websocket failed.');
  }
});

// Helpers
function startLogin(res, prompt) {
  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = generators.codeVerifier(43);
  // PKCE sends only the derived challenge to the IdP. The verifier is kept in
  // tokenStore and sent later during the token exchange.
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: authConfig.clientId,
    redirect_uri: authConfig.redirectUri,
    code_challenge: generators.codeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    scope: idpScope,
    state,
  });

  if (prompt) {
    params.set('prompt', prompt);
  }

  tokenStore[state] = { codeVerifier };
  res.redirect(`${authConfig.idpAuthorizeUri}?${params.toString()}`);
}

async function exchangeAuthorizationCode(code, state, codeVerifier) {
  // The authorization code is useless without the matching PKCE verifier, which
  // protects the callback from intercepted or replayed codes.
  const tokenRequestBody = new URLSearchParams({
    code,
    code_verifier: codeVerifier,
    grant_type: 'authorization_code',
    redirect_uri: authConfig.redirectUri,
    client_id: authConfig.clientId,
    client_secret: authConfig.clientSecret,
  });

  const idpTokenRes = await fetch(authConfig.idpTokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenRequestBody,
  });

  delete tokenStore[state];

  if (!idpTokenRes.ok) {
    console.error(await idpTokenRes.text());
    return null;
  }

  return idpTokenRes.json();
}

function createQlikJwt(email, name, sub) {
  // This JWT is intentionally short-lived: it is only a bridge token used to
  // ask Qlik Cloud for a browser-compatible session cookie.
  return jsonwebtoken.sign({
    jti: crypto.randomBytes(16).toString('hex'),
    // Prefixing the IdP subject creates a stable user identity namespace in Qlik.
    sub: `BackendApp|${sub}`,
    subType: 'user',
    email_verified: true,
    email,
    name,
  }, qlikConfig.privateKey, {
    keyid: qlikConfig.keyId,
    algorithm: 'RS256',
    issuer: qlikConfig.issuer,
    expiresIn: '1m',
    audience: 'qlik.api/login/jwt-session',
    notBefore: '0s',
  });
}

async function exchangeJwtForQlikCookie(token) {
  const resp = await fetch(`https://${qlikConfig.tenantUri}/login/jwt-session`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!resp.ok) {
    throw new Error(`Qlik JWT session request failed with status ${resp.status}: ${await resp.text()}`);
  }

  const cookies = getSetCookieHeaders(resp.headers);
  if (!cookies.length) {
    throw new Error('Qlik JWT session response did not include a set-cookie header.');
  }

  // Qlik returns Set-Cookie headers; the proxy stores only name=value pairs to
  // replay back to Qlik on later HTTP and websocket requests.
  return cookies.map((value) => value.split(';')[0]).join(';');
}

function getSetCookieHeaders(headers) {
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie();
  }

  return splitCombinedSetCookieHeader(headers.get('set-cookie'));
}

function splitCombinedSetCookieHeader(value) {
  // Older Node versions may combine Set-Cookie headers. Split only on commas
  // that look like the start of another cookie, not cookie attributes.
  return value ? value.split(/,(?=\s*[^;,]+=)/) : [];
}

function getQlikCookieFromSession(sessionData) {
  return sessionData?.qlikSession ? decodeURIComponent(sessionData.qlikSession) : '';
}

async function getQlikCookieFromSocket(req) {
  const appCookie = req.headers.cookie && parseCookie(req.headers.cookie)['connect.sid'];
  if (!appCookie) {
    return '';
  }

  // Websocket upgrades bypass Express middleware, so the signed session cookie
  // must be verified manually before loading the matching Redis session.
  const sessionId = cookieParser.signedCookie(appCookie, env.SESSION_SECRET);
  if (!sessionId) {
    return '';
  }

  return getQlikCookieFromSession(await getSessionFromStore(sessionId));
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

async function proxyPublicAsset(req, res, assetType) {
  try {
    // Static Qlik assets do not use the stored Qlik session cookie, but they
    // still need to be served through this origin for the embedded experience.
    const upstream = await fetch(`https://${qlikConfig.tenantUri}${req.originalUrl}`);
    setCors(res);
    res.set('Content-Type', upstream.headers.get('content-type'));
    await sendUpstream(res, upstream);
  } catch (err) {
    console.error(`Proxy /${assetType} failed:`, err.message);
    setCors(res);
    res.status(502).send(`Failed to reach Qlik Cloud ${assetType}.`);
  }
}

async function sendUpstream(res, upstream) {
  res.status(upstream.status);
  res.end(Buffer.from(await upstream.arrayBuffer()), 'binary');
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

function buildRedisOptions() {
  if (env.REDIS_URL) {
    return { url: env.REDIS_URL };
  }

  const options = {
    socket: {
      host: env.REDIS_HOST || 'localhost',
      port: Number(env.REDIS_PORT || 6379),
    },
  };

  if (env.REDIS_PASSWORD) {
    options.password = env.REDIS_PASSWORD;
  }

  return options;
}

function normalizeTenantHost(value) {
  return removeTrailingSlash(value || '').replace(/^https?:\/\//, '');
}

function removeTrailingSlash(value) {
  return value.replace(/\/$/, '');
}

function parseBoolean(value, fallback) {
  return value === undefined ? fallback : ['1', 'true', 'yes'].includes(value.toLowerCase());
}

function validateConfig() {
  const missing = Object.entries({
    tenantUri: qlikConfig.tenantUri,
    privateKey: qlikConfig.privateKey,
    keyId: qlikConfig.keyId,
    issuer: qlikConfig.issuer,
    webIntegrationId: qlikWebId,
    sessionSecret: env.SESSION_SECRET,
    clientId: authConfig.clientId,
    clientSecret: authConfig.clientSecret,
    idpUri: env.IDP_URI,
  }).filter(([, value]) => !value).map(([key]) => key);

  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}
