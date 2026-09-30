import { createHash, timingSafeEqual } from 'node:crypto';
import type { WorkOSStore } from './store.js';
import type { WorkOSConnectApplication } from './entities.js';

/**
 * The AuthKit domain acting as an OAuth 2.1 authorization server for MCP clients: what
 * `/oauth2/authorize`, `/oauth2/token` and `/oauth2/register` share with the discovery documents.
 * Kept out of the route files because the documents advertise exactly what the routes enforce, and
 * one list is what keeps the two from drifting.
 */

/** The scopes a production AuthKit domain advertises. A dynamically registered client is limited to these. */
export const AUTHKIT_OAUTH_SCOPES = ['email', 'offline_access', 'openid', 'profile'] as const;

/** Only S256: production advertises no other, and OAuth 2.1 drops `plain`. */
export const AUTHKIT_CODE_CHALLENGE_METHODS = ['S256'] as const;

/** `none` is a public client, which `/oauth2/register` maps to a PKCE-only application. */
export const AUTHKIT_TOKEN_ENDPOINT_AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'] as const;

/**
 * Whether the application is a public client: one that cannot keep a secret, so PKCE is its only
 * proof. `uses_pkce` is the field WorkOS gives an application for exactly this, and
 * `/oauth2/register` sets it for `token_endpoint_auth_method: none`.
 */
export function isPublicClient(application: WorkOSConnectApplication): boolean {
  return application.application_type === 'oauth' && application.uses_pkce;
}

/** RFC 7636 §4.6 for S256. Constant-time, because the verifier is a secret until the exchange. */
export function pkceMatches(codeVerifier: string, codeChallenge: string): boolean {
  const computed = Buffer.from(createHash('sha256').update(codeVerifier).digest('base64url'));
  const expected = Buffer.from(codeChallenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}

/** RFC 7636 §4.1: 43 to 128 unreserved characters. */
export function isValidCodeVerifier(value: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(value);
}

/**
 * RFC 8707 §2: a resource is an absolute URI with no fragment. Checked wherever a client hands one
 * over, so a malformed value is refused as `invalid_target` instead of being carried on a code.
 */
export function isValidResourceUri(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.hash === '' && !value.includes('#');
  } catch {
    return false;
  }
}

/**
 * The `aud` for a token bound to `resource`. It is the resource only when the environment has
 * registered it as an indicator; anything else, including no resource at all, falls back to the
 * application's `audience` and then its `client_id`, which is what this surface minted before
 * indicators existed.
 */
export function resolveAudience(
  ws: WorkOSStore,
  application: WorkOSConnectApplication,
  resource: string | null | undefined,
): string {
  if (resource && ws.authkitOauthResources.findOneBy('uri', resource)) return resource;
  return application.audience ?? application.client_id;
}

/** A `/oauth2/authorize` request that passed validation, held while the hosted sign-in runs. */
export interface ConnectAuthorizeRequest {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string | null;
  code_challenge_method: string | null;
  scope: string[];
  resource: string | null;
  expires_at: string;
}
