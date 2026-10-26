# Qlik Cloud JWT Proxy

Local Node/Express tutorial sample demonstrating the Qlik Cloud JWT session cookie proxy pattern. This app authenticates a user through an identity provider (IdP), creates a signed JWT for Qlik Cloud, stores the Qlik session cookie server-side, and proxies Qlik Cloud resources, REST API calls, Single API iframe content, and engine websockets from the same origin.

**This is a tutorial sample, not production-ready authentication infrastructure.** It intentionally simplifies IdP token validation and session management for educational purposes. For production use, implement proper token validation, issuer/audience checks, expiry validation, nonce handling, and other security hardening.

**This is a tutorial sample, not production-ready authentication infrastructure.** It validates IdP tokens through OpenID Connect discovery, including signature, issuer, audience, expiry, and nonce checks. Temporary OIDC login state is bound to the browser's Redis-backed Express session and consumed once at the callback. Production applications still need deployment-specific security hardening.

- Node.js 18 or newer
- Qlik Cloud tenant with JWT identity provider configuration (get the tenant URI, key ID, and private key from your Qlik admin)
- Web integration ID from Qlik Cloud
- Identity provider (IdP) set up as an OAuth2 application with:
  - Client ID and client secret
  - Authorization endpoint: `{IDP_URI}/authorize`
  - Token endpoint: `{IDP_URI}/oauth/token`
  - Callback URL set to `http://localhost:3000/login/callback` (adjust for your setup)
- Redis running locally or access to a Redis-compatible instance

### Setup

### Prerequisites

- Node.js 22 or 24 LTS
- Qlik Cloud tenant with JWT identity provider configuration (get the tenant URI, key ID, and private key from your Qlik admin)
- Web integration ID from Qlik Cloud
- OpenID Connect identity provider (IdP), such as Auth0, with:
  - Client ID and client secret
  - An issuer URL that supports OpenID Connect discovery and publishes signing keys
  - Support for the `client_secret_post` token endpoint authentication method
  - Callback URL set to `http://localhost:3000/login/callback` (adjust for your setup)
- Redis running locally or access to a Redis-compatible instance

### Setup

1. Clone this repository.
2. Install dependencies:

```sh
npm install
```

3. Copy `.env.example` to `.env` and fill in all required values (see [Required Environment Variables](#required-environment-variables) below).

4. Start Redis locally:

```sh
docker compose up -d redis
```

Or point to a hosted Redis instance by setting `REDIS_URL` in `.env`.

5. Start the app:

```sh
npm start
```

6. Open `http://localhost:3000` in your browser, complete the IdP login, and verify that Qlik content loads.

## Required Environment Variables

Copy `.env.example` to `.env`, then set these values before running the sample:

| Category | Variables | Purpose |
| --- | --- | --- |
| Qlik Cloud | `TENANT_URI`, `WEB_INTEGRATION_ID`, `QLIK_JWT_ISSUER`, `QLIK_JWT_KEY_ID`, `QLIK_JWT_PRIVATE_KEY` | JWT identity provider configuration from Qlik Cloud |
| Identity Provider | `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`, `IDP_URI`, `IDP_REDIRECT_URI` | OpenID Connect configuration for your IdP (e.g., Auth0) |
| Session | `SESSION_SECRET`, `SESSION_MAX_AGE_MS` | Session management |
| Local App | `APP_BASE_URL` | Public URL of this proxy (usually `http://localhost:3000` for local development) |
| Redis | `REDIS_HOST`, `REDIS_PORT` or `REDIS_URL` | Session storage (see [Redis Configuration](#redis-configuration)) |
| Cookies | `COOKIE_SECURE` | Set to `true` if using HTTPS |
| Demo Content | `APP_ID`, `SHEET_ID`, `IFRAME_APP_ID`, `IFRAME_SHEET_ID`, `QLIK_EMBED_APP_ID`, `QLIK_EMBED_OBJECT_ID`, `QLIK_THEME` | Qlik app, sheet, and object IDs to display in the sample (optional) |

### Redis Configuration

The app uses Redis to store Qlik session cookies server-side. Choose one of these approaches:

**Option 1: Local Redis (Docker Compose)**

The default `.env.example` uses `REDIS_HOST=localhost` and `REDIS_PORT=6379`. Start Redis with:

```sh
docker compose up -d redis
```

**Option 2: Hosted Redis**

Set `REDIS_URL` in `.env` (for example, `redis://localhost:6379`). This takes precedence over `REDIS_HOST` and `REDIS_PORT`:

```env
REDIS_URL=redis://localhost:6379
# REDIS_HOST=localhost
# REDIS_PORT=6379
```

The app supports `REDIS_PASSWORD` if your Redis instance requires authentication.

### Identity Provider (IdP) Configuration

Set `IDP_URI` to your provider's OpenID Connect issuer URL, for example `https://your-tenant.eu.auth0.com`. The app retrieves the authorize endpoint, token endpoint, and public signing keys through OpenID Connect discovery when it starts. It uses `openid-client` to validate the ID token before reading its user claims.

The sample uses `client_secret_post` for the token exchange. Providers that require a different client authentication method may need a change to the client configuration in `index.js`. Keep `openid` in `IDP_SCOPE`, and request the `email` and `profile` scopes so the sample receives the required user claims.

Set `IDP_REDIRECT_URI` to match your IdP's allowed callback URLs. For local development, use `http://localhost:3000/login/callback`. If you use a tunnel or reverse proxy, update this to the public URL and reconfigure your IdP.

### Other Configuration Notes

- **`APP_BASE_URL`**: The public URL of this proxy. For local development, it defaults to `http://localhost:3000`. If you expose the app via a tunnel or reverse proxy, set this to that URL and update your IdP callback configuration. An HTTPS-terminating reverse proxy also requires an appropriate Express `trust proxy` configuration before secure session cookies will work.

- **`QLIK_JWT_PRIVATE_KEY`**: Store the Qlik JWT private key with escaped newlines:

```env
QLIK_JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

- **`SESSION_SECRET`**: Generate a random value with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.

- **Demo content**: The backend exposes demo content values to the browser through `/app-config.js`. Set the Qlik app, sheet, and object IDs in your `.env` file (see [Required Environment Variables](#required-environment-variables)), and they will be automatically available to both the quickstart and the `qlik-embed` examples.

## Scripts

```sh
npm start          # Run the app
npm run dev        # Run with Node.js watch mode
npm run check      # Check backend JavaScript syntax
npm test           # Validate ID token verification with a local mock IdP
```

## How It Works

- **Session storage**: The browser receives a local session cookie (Express session). The Qlik session cookie is stored server-side in Redis and attached to requests when proxying to Qlik Cloud. This pattern protects the Qlik session from frontend access.

- **Redis for multi-instance deployment**: In development, you can use local Redis. For production deployments with multiple app instances, use a managed Redis service so all instances share the same session store.

- **IdP integration**: The app uses PKCE (Proof Key for Code Exchange) and a nonce during login. The pending login details are held in the browser's server-side session and removed on the callback. The IdP token is validated against the provider's signing keys and expected claims before creating a Qlik JWT and exchanging it for a Qlik session cookie.

- **Proxying**: The app proxies Qlik API requests (`/api/v1/*`), Single API content (`/single/*`), static assets (`/resources/*`, `/assets/*`), and websocket connections (`/app/*`) through the same origin. For `/single/*` and `/app/*`, the proxy requires a Qlik session. For `/api/v1/*`, the proxy forwards the stored Qlik session cookie when one exists; otherwise, it forwards the request without a cookie and lets Qlik Cloud return the appropriate public response or authorization error.

- **GET-only sample**: The sample proxies `GET` requests only. Support for other HTTP methods, such as `POST`, `PUT`, or `DELETE`, is outside the scope of this tutorial.

## Troubleshooting

- **Redis connection errors**: Ensure Redis is running. Check that `REDIS_HOST`, `REDIS_PORT`, or `REDIS_URL` are correct and the instance is reachable.

- **IdP callback failures**: Verify that `IDP_REDIRECT_URI` matches the callback URL allow-listed in your IdP configuration.

- **Qlik session not loading**: Ensure `TENANT_URI`, `WEB_INTEGRATION_ID`, and the JWT keys are correct. Check that your Qlik JWT identity provider is properly configured in Qlik Cloud.

- **403 / CSRF token errors**: The app requires CSRF tokens from Qlik. If errors persist, verify that the Qlik session is being stored and retrieved correctly from Redis.
