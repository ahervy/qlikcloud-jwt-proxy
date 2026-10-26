import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { after, before, test } from 'node:test';
import jsonwebtoken from 'jsonwebtoken';
import { createIdpClient, takeLoginState, validateIdpCallback } from '../oidc.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { privateKey: otherKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', use: 'sig', alg: 'RS256' };

const clientId = 'test-client';
const redirectUri = 'http://localhost:3000/login/callback';
const state = 'test-state';
const loginState = { codeVerifier: 'test-code-verifier', nonce: 'test-nonce' };

test('consumes login state only from the browser session that started it', () => {
  const browserSession = { pendingLogin: { state, ...loginState } };
  const otherBrowserSession = {};

  assert.equal(takeLoginState(otherBrowserSession, state), null);
  assert.equal(takeLoginState(browserSession, 'different-state'), null);
  assert.ok(browserSession.pendingLogin);

  assert.deepEqual(takeLoginState(browserSession, state), loginState);
  assert.equal(browserSession.pendingLogin, undefined);
  assert.equal(takeLoginState(browserSession, state), null);
});

let issuerUrl;
let client;
let server;
let tokenOverrides = {};
let signingKey = privateKey;

before(async () => {
  server = createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');

    if (req.url === '/.well-known/openid-configuration') {
      res.end(JSON.stringify({
        issuer: issuerUrl,
        authorization_endpoint: `${issuerUrl}/authorize`,
        token_endpoint: `${issuerUrl}/oauth/token`,
        jwks_uri: `${issuerUrl}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      }));
      return;
    }

    if (req.url === '/jwks') {
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }

    if (req.url === '/oauth/token' && req.method === 'POST') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const fields = new URLSearchParams(body);
      assert.equal(fields.get('code_verifier'), loginState.codeVerifier);
      assert.equal(fields.get('client_id'), clientId);
      assert.equal(fields.get('client_secret'), 'test-secret');

      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: issuerUrl,
        aud: clientId,
        sub: 'user-123',
        email: 'user@example.com',
        name: 'Test User',
        nonce: loginState.nonce,
        iat: now,
        exp: now + 300,
        ...tokenOverrides,
      };
      const idToken = jsonwebtoken.sign(claims, signingKey, {
        algorithm: 'RS256',
        keyid: 'test-key',
      });
      res.end(JSON.stringify({ access_token: 'test-access-token', token_type: 'Bearer', id_token: idToken }));
      return;
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuerUrl = `http://127.0.0.1:${server.address().port}`;
  client = await createIdpClient({
    idpUri: issuerUrl,
    clientId,
    clientSecret: 'test-secret',
    redirectUri,
  });
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('accepts a signed ID token with valid issuer, audience, expiry, and nonce', async () => {
  const claims = await validateIdpCallback(client, redirectUri, 'test-code', state, loginState);
  assert.equal(claims.email, 'user@example.com');
  assert.equal(claims.sub, 'user-123');
});

for (const [name, overrides] of [
  ['wrong issuer', { iss: 'https://wrong-issuer.example' }],
  ['wrong audience', { aud: 'different-client' }],
  ['expired ID token', { exp: 1 }],
  ['wrong nonce', { nonce: 'different-nonce' }],
]) {
  test(`rejects ${name}`, async () => {
    tokenOverrides = overrides;
    try {
      await assert.rejects(validateIdpCallback(client, redirectUri, 'test-code', state, loginState));
    } finally {
      tokenOverrides = {};
    }
  });
}

test('rejects an ID token signed by an unknown key', async () => {
  signingKey = otherKey;
  try {
    await assert.rejects(validateIdpCallback(client, redirectUri, 'test-code', state, loginState));
  } finally {
    signingKey = privateKey;
  }
});
