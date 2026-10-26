import { Issuer } from 'openid-client';

// Discover the IdP's standard OIDC endpoints and the location of its signing keys.
// This avoids relying on provider-specific endpoint URLs.
export async function createIdpClient(config) {
  const issuer = await Issuer.discover(config.idpUri);
  return new issuer.Client({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uris: [config.redirectUri],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
  });
}

// Exchange the authorization code for tokens.
// openid-client also validates the ID token, including its signature,
// issuer, audience, expiration, and nonce.
export async function validateIdpCallback(client, redirectUri, code, state, loginState) {
  const tokens = await client.callback(redirectUri, { code, state }, {
    state,
    nonce: loginState.nonce,
    code_verifier: loginState.codeVerifier,
  });
  return tokens.claims();
}

// Retrieve the pending login from the browser's server-side session.
// This prevents a callback started in one browser session from being
// completed in another, and prevents the state from being reused.
export function takeLoginState(session, returnedState) {
  const pendingLogin = session?.pendingLogin;
  if (!returnedState || !pendingLogin || pendingLogin.state !== returnedState) {
    return null;
  }

  delete session.pendingLogin;
  return { codeVerifier: pendingLogin.codeVerifier, nonce: pendingLogin.nonce };
}
