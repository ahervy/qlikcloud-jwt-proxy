# Qlik Cloud JWT Proxy

Local Node/Express version of the Qlik Cloud JWT session cookie proxy quickstart. The app keeps the tutorial scope: authenticate a user through a web app IdP, create a signed JWT for Qlik Cloud, store the Qlik session cookie server-side, and proxy Qlik Cloud resources, REST calls, Single API iframe content, and engine websockets from a same-origin local app.

For new production embedded analytics projects, evaluate Qlik OAuth machine-to-machine impersonation first. Keep this JWT session cookie proxy pattern for cases where OAuth impersonation cannot be used and you specifically need the session-cookie proxy architecture.

This sample focuses on the Qlik JWT proxy flow. It simplifies IdP token validation for tutorial purposes and must not be used as production authentication logic without proper token validation, issuer/audience checks, expiry checks, nonce handling, and other hardening.

Before publishing, replace any placeholder clone URL in `docs/quickstart-qlik-jwt-proxy.mdx` with the final public repository URL.

## Run Locally

1. Install Node.js 18 or newer.
2. Create a Qlik Cloud JWT identity provider configuration and web integration id.
3. Create or configure your web application identity provider client. Its callback URL must match `redirectUri`.
4. Copy `.env.example` to `.env` and fill in the values.
5. Install dependencies:

```sh
npm install
```

1. Start Redis locally, or point `REDIS_URL`/`REDIS_HOST`/`redis_port` to a hosted Redis instance.

```sh
docker compose up -d redis
```

1. Start the app:

```sh
npm start
```

1. Open `http://localhost:3000`.

## Required Environment Variables

Copy `.env.example` to `.env`, then set these values before running the tutorial:

| Area | Variables |
| --- | --- |
| Startup | `tenantUri`, `webIntegrationId`, `issuer`, `keyId`, `privateKey`, `clientId`, `clientSecret`, `idpUri`, `sessionSecret` |
| Local URL | `APP_BASE_URL`, and `redirectUri` if your IdP requires an exact callback value |
| Redis | Use the local defaults, or set `REDIS_URL` for a hosted Redis-compatible instance |
| Demo content | `APP_ID`, `SHEET_ID`, `IFRAME_APP_ID`, `IFRAME_SHEET_ID`, `QLIK_THEME` |

## Important Configuration

`APP_BASE_URL` is the public URL of this proxy. For local development it is usually `http://localhost:3000`. If you use a tunnel or HTTPS reverse proxy, set this value to that URL and update the IdP callback URL.

`redirectUri` defaults to `${APP_BASE_URL}/login/callback`, but it is listed in `.env.example` because most IdPs require an exact allow-list value.

`privateKey` can be stored with escaped newlines, for example:

```env
privateKey="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

The Capability API and Single API iframe examples use the demo content variables in `.env`. The `qlik-embed` example is intentionally simpler for this tutorial: edit the `app-id` and `object-id` attributes directly in `index.html`.

## Scripts

```sh
npm start
npm run dev
npm run check
```

## Notes

The browser only receives the local session cookie. The Qlik session cookie is stored in Redis and attached by the backend when proxying requests to Qlik Cloud.

Use local Redis for development. Use a managed Redis-compatible service for deployed multi-instance environments. The default in-memory session store from `express-session` is only suitable for short local experiments because sessions vanish on restart and it is not designed for production.
