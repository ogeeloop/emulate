import type { Context } from 'hono';
import { type RouteContext, OauthApiError, generateId, generateUlid } from '../../core/index.js';
import { getWorkOSStore } from '../store.js';
import {
  activeOrganizationsFor,
  assertAllowedRedirectUri,
  emitAuthenticationEvent,
  expiresIn,
  isExpired,
  startLoginSession,
} from '../helpers.js';
import {
  AUTHKIT_OAUTH_SCOPES,
  isPublicClient,
  isValidCodeVerifier,
  isValidResourceUri,
  pkceMatches,
  resolveAudience,
  type ConnectAuthorizeRequest,
} from '../authkit-oauth.js';
import { STORE_KEYS, STORE_KEY_PREFIXES } from '../constants.js';
import { renderOAuthErrorPage } from '../login-page.js';
import type { EventBus } from '../event-bus.js';
import type { WorkOSConnectApplication, WorkOSSession, WorkOSUser } from '../entities.js';

/**
 * Connect token exchange (OAuth 2.0 `client_credentials` and `authorization_code`).
 *
 * This endpoint is deliberately hand-authored: it is absent from the WorkOS OpenAPI
 * spec at every version (the spec's `/sso/token` only documents `authorization_code`),
 * so it cannot be generated. It mirrors how `/user_management/authenticate` already
 * implements grant types beyond what the spec describes — runtime OAuth behavior, not
 * a spec-described resource.
 *
 * A service exchanges its seeded `client_id` + `client_secret` (a Connect Application
 * of type `m2m`, see the `connectApplications` seed block) for a signed JWT. The token
 * is signed with the same key the emulator exposes at `/sso/jwks/:client_id` and
 * `/oauth2/jwks`, so a consumer validating with JWKS (e.g. `jose`, checking `iss`/`aud`)
 * verifies it without any emulator-specific shims.
 *
 * The claim set mirrors a production M2M token exactly, because the SDKs parse it:
 * granted scopes ride in a space-delimited `scope` string (RFC 8693 §4.2 — the Node
 * SDK reads `payload.scope`), and every token carries a `jti`, without which the SDKs'
 * M2M claim guard rejects an otherwise-valid token. Neither is emulator-flavored: a
 * scopes *array*, or an omitted `jti`, would pass locally and fail in production.
 *
 * Failures throw `OauthApiError`, the same RFC 6749 §5.2 renderer `/sso/token` and the
 * OAuth-shaped authenticate grants use. This endpoint had a local `oauthError()` helper that
 * built the identical body by hand, which meant the OAuth envelope was defined in two places
 * and only one of them was reachable from anywhere else.
 *
 * The same endpoints are the AuthKit domain's OAuth 2.1 authorization server for MCP clients:
 * an application with no `login_url` signs its users in on AuthKit's hosted page (the one
 * `/user_management/authorize` serves), a public client proves itself by PKCE alone, and the
 * token response carries a rotating refresh token. `iss` on those tokens is the bare AuthKit
 * domain rather than the per-client `/user_management/{client_id}` issuer that
 * `/user_management/authenticate` tokens carry (a requirement taken from an observed production
 * AuthKit domain's Connect tokens).
 *
 * Client failures at the token endpoint follow what was observed against a production AuthKit
 * domain, 2026-09-30: `401 invalid_client` with `WWW-Authenticate: Basic realm="AuthKit"`, "Missing
 * authorization header." when no client is named and "Application not found." for an unknown
 * `client_id` under every grant type, with the client lookup running before grant-type validation.
 * That deliberately replaces this endpoint's earlier 400s for a missing or unknown client.
 */

const TOKEN_TTL_SECONDS = 3600;

interface TokenParams {
  grantType?: string;
  clientId?: string;
  clientSecret?: string;
  /** Where the secret came from, since a registered client may be limited to one of the two. */
  secretVia?: 'basic' | 'post';
  scope?: string;
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
  refreshToken?: string;
  /** RFC 8707 `resource`. Only the first is read; a repeated parameter is not supported. */
  resource?: string;
}

/**
 * Decode a Basic-auth credential component. RFC 6749 §2.3.1 form-urlencodes the
 * client_id/secret before base64, but many clients send them literally; a literal `%`
 * makes decodeURIComponent throw. Decode when valid, otherwise use the raw value so a
 * pinned secret containing `%` yields invalid_client rather than a 500.
 */
function formDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Read client credentials and grant params from the request. Supports both the
 * form-encoded body services typically send and a JSON body, plus HTTP Basic auth
 * for the client credentials (RFC 6749 §2.3.1) as a fallback when they are not in
 * the body. Body params take precedence over the Basic header.
 */
async function readTokenParams(c: Context): Promise<TokenParams> {
  const contentType = c.req.header('content-type') ?? '';

  let raw: Record<string, unknown> = {};
  if (contentType.includes('application/json')) {
    try {
      const body = await c.req.json();
      if (body && typeof body === 'object' && !Array.isArray(body)) raw = body as Record<string, unknown>;
    } catch {
      // fall through to empty params; missing grant_type yields a clear error below
    }
  } else {
    const form = await c.req.parseBody();
    raw = form as Record<string, unknown>;
  }

  const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

  let clientId = str(raw.client_id);
  let clientSecret = str(raw.client_secret);
  let secretVia: 'basic' | 'post' | undefined = clientSecret ? 'post' : undefined;

  const authHeader = c.req.header('authorization');
  if ((!clientId || !clientSecret) && authHeader && /^basic\s/i.test(authHeader)) {
    const decoded = Buffer.from(authHeader.replace(/^basic\s+/i, '').trim(), 'base64').toString('utf-8');
    const sep = decoded.indexOf(':');
    if (sep >= 0) {
      clientId = clientId || formDecode(decoded.slice(0, sep));
      if (!clientSecret) {
        clientSecret = formDecode(decoded.slice(sep + 1));
        secretVia = 'basic';
      }
    }
  }

  return {
    grantType: str(raw.grant_type),
    clientId,
    clientSecret,
    secretVia,
    scope: str(raw.scope),
    code: str(raw.code),
    redirectUri: str(raw.redirect_uri),
    codeVerifier: str(raw.code_verifier),
    refreshToken: str(raw.refresh_token),
    resource: str(raw.resource),
  };
}

export function oauthRoutes(ctx: RouteContext): void {
  const { app, store, jwt } = ctx;
  const ws = getWorkOSStore(store);

  /**
   * Answer an authorize failure the way RFC 6749 §4.1.2.1 has it once the callback is trusted: as
   * an error on the redirect_uri, with the caller's `state` echoed back. Before that point there
   * is nowhere safe to send the browser, which is why the earlier failures stay plain responses.
   */
  const redirectError = (
    c: Context,
    redirectUri: string,
    state: string | undefined,
    error: string,
    message: string,
  ) => {
    const redirect = new URL(redirectUri);
    redirect.searchParams.set('error', error);
    redirect.searchParams.set('error_description', message);
    if (state !== undefined) redirect.searchParams.set('state', state);
    return c.redirect(redirect.toString(), 302);
  };

  // The OAuth browser entry point. Standalone Connect (an application with a `login_url`) and the
  // AuthKit-domain authorization server share it, and the application decides which one runs.
  // Like /oauth2/token, this route is hand-authored because the public spec only describes the
  // server-side completion of the first and none of the second.
  app.get('/oauth2/authorize', (c) => {
    const { client_id: clientId, redirect_uri: redirectUri, response_type: responseType, state } = c.req.query();
    if (!clientId || !redirectUri) {
      throw new OauthApiError(400, 'invalid_request', 'client_id and redirect_uri are required.');
    }
    if (responseType !== 'code') {
      throw new OauthApiError(400, 'unsupported_response_type', 'response_type must be code.');
    }
    const application = ws.connectApplications.findOneBy('client_id', clientId);
    // An unknown client is a redirect to the error page, not an API error (observed against a
    // production AuthKit domain, 2026-09-30): the caller is a browser with no callback to trust yet.
    if (!application) {
      return c.redirect(`${new URL(c.req.url).origin}/oauth2/error?error=application_not_found`, 302);
    }
    if (application.application_type !== 'oauth') {
      throw new OauthApiError(400, 'unauthorized_client', 'The client must be an OAuth application.');
    }
    if (application.redirect_uris.length > 0 && !application.redirect_uris.includes(redirectUri)) {
      throw new OauthApiError(400, 'invalid_request', 'redirect_uri is not registered for this application.');
    }
    assertAllowedRedirectUri(redirectUri, store);

    if (application.login_url) {
      assertAllowedRedirectUri(application.login_url, store);
      const login = new URL(application.login_url);
      const session = ws.externalAuthSessions.insert({
        client_id: clientId,
        redirect_uri: redirectUri,
        state: state ?? null,
        expires_at: expiresIn(10),
        completed_at: null,
        redeemed_at: null,
        user_id: null,
      });
      login.searchParams.set('external_auth_id', session.id);
      return c.redirect(login.toString(), 302);
    }

    // No login_url: the user signs in on AuthKit's hosted page. Validate everything a client could
    // get wrong now, while a redirect_uri exists to report it on, then park the request and send
    // the browser to the sign-in page `/user_management/authorize` serves, which finishes it.
    const fail = (error: string, message: string) => redirectError(c, redirectUri, state, error, message);

    // PKCE (RFC 7636). S256 only — production advertises no other method — and required of a
    // public client, whose challenge is the only thing that later proves the code is its own.
    const codeChallenge = c.req.query('code_challenge');
    const codeChallengeMethod = c.req.query('code_challenge_method');
    if (codeChallengeMethod !== undefined && codeChallengeMethod !== 'S256') {
      return fail('invalid_request', 'code_challenge_method must be S256.');
    }
    if (codeChallenge === undefined && codeChallengeMethod !== undefined) {
      return fail('invalid_request', 'code_challenge is required when code_challenge_method is set.');
    }
    if (codeChallenge !== undefined && !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
      return fail('invalid_request', 'code_challenge must be 43 to 128 base64url characters.');
    }
    if (codeChallenge === undefined && isPublicClient(application)) {
      return fail('invalid_request', 'code_challenge is required for public clients.');
    }

    // An application configured with scopes is limited to them; one with none (a seeded app that
    // never listed any) is offered the standard set an AuthKit domain advertises.
    const allowedScopes = application.scopes.length > 0 ? application.scopes : [...AUTHKIT_OAUTH_SCOPES];
    const scopeParam = c.req.query('scope');
    const scopes = scopeParam?.trim() ? scopeParam.trim().split(/\s+/) : allowedScopes;
    const unknownScopes = scopes.filter((s) => !allowedScopes.includes(s));
    if (unknownScopes.length > 0) {
      return fail(
        'invalid_scope',
        `The requested scope(s) are not available to this application: ${unknownScopes.join(', ')}.`,
      );
    }

    // RFC 8707. Any well-formed resource is accepted here, registered or not; whether it becomes
    // the token's `aud` is decided when a token is minted (see resolveAudience).
    const resource = c.req.query('resource') ?? null;
    if (resource !== null && !isValidResourceUri(resource)) {
      return fail('invalid_target', 'resource must be an absolute URI without a fragment.');
    }

    // Sweep requests no sign-in ever finished, as the interactive login tokens are swept, so the
    // store holds the last ten minutes rather than one per abandoned browser tab.
    store.deleteDataByPrefix(STORE_KEY_PREFIXES.connectAuthorize, (v) =>
      isExpired((v as ConnectAuthorizeRequest).expires_at),
    );
    const requestId = generateId('connect_req');
    const request: ConnectAuthorizeRequest = {
      client_id: clientId,
      redirect_uri: redirectUri,
      state: state ?? null,
      code_challenge: codeChallenge ?? null,
      code_challenge_method: codeChallenge === undefined ? null : 'S256',
      scope: scopes,
      resource,
      expires_at: expiresIn(10),
    };
    store.setData(`${STORE_KEY_PREFIXES.connectAuthorize}${requestId}`, request);

    const signIn = new URL(`${new URL(c.req.url).origin}/user_management/authorize`);
    signIn.searchParams.set('connect_request', requestId);
    // The two hints the sign-in page understands; neither widens what the request was validated for.
    for (const hint of ['login_hint', 'organization_id']) {
      const value = c.req.query(hint);
      if (value) signIn.searchParams.set(hint, value);
    }
    return c.redirect(signIn.toString(), 302);
  });

  // Where /oauth2/authorize sends a browser it cannot serve: 200 text/html, reflecting the
  // `error_description` it is given (observed against a production AuthKit domain, 2026-09-30).
  // Reflected text is escaped by the page renderer.
  app.get('/oauth2/error', (c) =>
    c.html(
      renderOAuthErrorPage({
        error: c.req.query('error') ?? 'invalid_request',
        description: c.req.query('error_description'),
      }),
    ),
  );

  /** A session for a user who has just signed in through the hosted page, as a fresh authenticate grant creates one. */
  const startSession = (
    c: Context,
    user: WorkOSUser,
    organizationId: string | null,
    authCode: { auth_method: string | null; step_up_method: string | null },
  ) => {
    // What the interactive gates left on the code decides the method, as in the authenticate
    // grant: the gate's method for the event, the primary method for the session it records.
    const authMethod = authCode.step_up_method ?? authCode.auth_method ?? 'OAuth';
    const sessionAuthMethod = authCode.step_up_method && authCode.auth_method ? authCode.auth_method : authMethod;
    const ipAddress = c.req.header('x-forwarded-for') ?? null;
    const userAgent = c.req.header('user-agent') ?? null;
    const session = startLoginSession(ws, {
      user,
      organizationId,
      ipAddress,
      userAgent,
      authMethod: sessionAuthMethod,
    });
    emitAuthenticationEvent({
      eventBus: store.getData<EventBus>(STORE_KEYS.eventBus),
      method: authMethod,
      status: 'succeeded',
      userId: user.id,
      email: user.email,
      ipAddress,
      userAgent,
    });
    return session;
  };

  /**
   * The token response for a user signed in through the hosted page: a Connect access token and a
   * refresh token. Known requirements of a Connect token: `iss` is the bare AuthKit domain, and it
   * carries `aud`, `sub` (the user id), `client_id` and `exp`. The rest of the claim set (`sid`,
   * `jti`, `org_id`, a space-delimited `scope`, and the absence of email, role, permissions and
   * JWT-template claims) is an emulator choice: production's full set was not captured.
   */
  const issueUserTokens = (
    application: WorkOSConnectApplication,
    session: WorkOSSession,
    scope: string[],
    resource: string | null,
  ) => {
    const accessToken = jwt.sign(
      {
        sub: session.user_id,
        sid: session.id,
        jti: generateUlid(),
        org_id: session.organization_id ?? undefined,
        client_id: application.client_id,
        scope: scope.join(' '),
        aud: resolveAudience(ws, application, resource),
      },
      { expiresIn: TOKEN_TTL_SECONDS },
    );
    const body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: TOKEN_TTL_SECONDS,
      scope: scope.join(' '),
    };
    // A client registered without the refresh_token grant is not given one. The resource and scope
    // ride on the token so they survive every rotation.
    if (!application.grant_types || application.grant_types.includes('refresh_token')) {
      body.refresh_token = ws.refreshTokens.insert({
        token: generateId('ref'),
        user_id: session.user_id,
        organization_id: session.organization_id,
        session_id: session.id,
        expires_at: expiresIn(30 * 24 * 60),
        client_id: application.client_id,
        connect: { scope, resource },
      }).token;
    }
    return body;
  };

  /** RFC 6749 §3.3 narrowing: a request may ask for fewer scopes than were granted, never more. */
  const narrowScope = (granted: string[], requested: string | undefined): string[] => {
    if (!requested || requested.trim().length === 0) return granted;
    const scopes = requested.trim().split(/\s+/);
    const unknown = scopes.filter((s) => !granted.includes(s));
    if (unknown.length > 0) {
      throw new OauthApiError(
        400,
        'invalid_scope',
        `The application is not granted the requested scope(s): ${unknown.join(', ')}.`,
      );
    }
    return scopes;
  };

  /**
   * RFC 8707 §2.2 on the token request: the grant is bound to the resource it was authorized for, so
   * the request may restate that resource or omit it. Anything else is `invalid_target`, including a
   * resource named for a grant that was authorized for none: a grant cannot pick one up later.
   */
  const bindResource = (bound: string | null, requested: string | undefined): string | null => {
    if (requested === undefined) return bound;
    if (!isValidResourceUri(requested)) {
      throw new OauthApiError(400, 'invalid_target', 'resource must be an absolute URI without a fragment.');
    }
    if (requested !== bound) {
      throw new OauthApiError(400, 'invalid_target', 'resource does not match the resource the grant was issued for.');
    }
    return bound;
  };

  const invalidClient = (description: string) =>
    new OauthApiError(401, 'invalid_client', description, { 'WWW-Authenticate': 'Basic realm="AuthKit"' });

  app.post('/oauth2/token', async (c) => {
    const {
      grantType,
      clientId,
      clientSecret,
      secretVia,
      scope,
      code,
      redirectUri,
      codeVerifier,
      refreshToken,
      resource,
    } = await readTokenParams(c);

    // Client first, grant type second: an unknown client is refused the same way whatever grant it
    // names, including an unsupported one (observed against a production AuthKit domain, 2026-09-30).
    if (!clientId) throw invalidClient('Missing authorization header.');
    const application = ws.connectApplications.findOneBy('client_id', clientId);
    if (!application) throw invalidClient('Application not found.');

    if (grantType !== 'client_credentials' && grantType !== 'authorization_code' && grantType !== 'refresh_token') {
      throw new OauthApiError(
        400,
        'unsupported_grant_type',
        `The grant type is not supported: ${grantType ?? '(none)'}`,
      );
    }

    const matchedSecret = clientSecret
      ? ws.clientSecrets.findBy('application_id', application.id).find((s) => s.value === clientSecret)
      : undefined;
    if (clientSecret && !matchedSecret) throw invalidClient('Invalid client ID or secret.');
    // A dynamically registered client authenticates the way it registered to: Basic or in the
    // body, not either. Seeded applications registered for nothing, so they accept both.
    const registeredMethod = application.token_endpoint_auth_method;
    if (
      matchedSecret &&
      ((registeredMethod === 'client_secret_basic' && secretVia !== 'basic') ||
        (registeredMethod === 'client_secret_post' && secretVia !== 'post'))
    ) {
      throw invalidClient(`This client is registered for ${registeredMethod}.`);
    }
    // A public client authenticates by its PKCE verifier, so for the two grants a user sign-in
    // produces it may present no secret at all. One that does present a secret is held to it.
    if (!clientSecret && !(grantType !== 'client_credentials' && isPublicClient(application))) {
      throw invalidClient('Missing authorization header.');
    }
    const expectedType = grantType === 'client_credentials' ? 'm2m' : 'oauth';
    if (application.application_type !== expectedType) {
      throw new OauthApiError(
        400,
        'unauthorized_client',
        `The client is not authorized to use the ${grantType} grant type.`,
      );
    }

    if (grantType !== 'client_credentials' && application.grant_types && !application.grant_types.includes(grantType)) {
      throw new OauthApiError(
        400,
        'unauthorized_client',
        `The client is not registered for the ${grantType} grant type.`,
      );
    }

    let response: Record<string, unknown>;

    if (grantType === 'refresh_token') {
      if (!refreshToken) throw new OauthApiError(400, 'invalid_request', 'refresh_token is required.');
      // Rotation as /user_management/authenticate does it: the presented token is spent for a
      // fresh one on the same session, so a token that has been used once answers invalid_grant.
      // Bound to the client it was issued to, so one application cannot redeem another's.
      const stored = ws.refreshTokens.findOneBy('token', refreshToken);
      if (!stored || !stored.connect || stored.client_id !== clientId) {
        throw new OauthApiError(400, 'invalid_grant', 'Invalid refresh token.');
      }
      if (isExpired(stored.expires_at)) {
        ws.refreshTokens.delete(stored.id);
        throw new OauthApiError(400, 'invalid_grant', 'Refresh token has expired.');
      }
      // Unlike authenticate, a revoked session ends its refresh tokens too: signing a person out
      // of an MCP client has to stop that client minting tokens for them.
      const session = ws.sessions.get(stored.session_id);
      if (!ws.users.get(stored.user_id) || !session || session.status !== 'active') {
        throw new OauthApiError(400, 'invalid_grant', 'Invalid refresh token.');
      }
      // Validated before the token is spent, so a bad `scope` or `resource` costs nothing.
      const granted = narrowScope(stored.connect.scope, scope);
      const bound = bindResource(stored.connect.resource, resource);
      ws.refreshTokens.delete(stored.id);
      // The narrowed scope and the bound resource carry forward; a narrowing is not undone by the next refresh.
      response = issueUserTokens(application, session, granted, bound);
    } else if (grantType === 'authorization_code') {
      if (!code || !redirectUri) {
        throw new OauthApiError(400, 'invalid_request', 'code and redirect_uri are required.');
      }
      // Bind the code to this flow, client, and exact callback before consuming it. Codes from
      // Standalone Connect (external_auth) and from the hosted sign-in (connect) are redeemable
      // here; an AuthKit code from /user_management/authorize is /authenticate's, not this endpoint's.
      const authCode = ws.authCodes.findOneBy('code', code);
      if (
        !authCode ||
        isExpired(authCode.expires_at) ||
        (authCode.auth_method !== 'external_auth' && !authCode.connect) ||
        authCode.client_id !== clientId ||
        authCode.redirect_uri !== redirectUri ||
        !ws.users.get(authCode.user_id)
      ) {
        throw new OauthApiError(400, 'invalid_grant', 'The authorization code has expired or is invalid.');
      }

      if (!authCode.connect && !matchedSecret) {
        // Standalone Connect has no PKCE: the secret is the whole client authentication there.
        throw new OauthApiError(400, 'invalid_request', 'client_id and client_secret are required.');
      }

      if (authCode.connect) {
        // PKCE (RFC 7636 §4.6). A code that carries a challenge is redeemed only with its
        // verifier, whoever the client is; a public client's code must carry one, because for it
        // the verifier is the whole proof (authorize already refuses to mint one without).
        if (authCode.code_challenge) {
          if (!codeVerifier) throw new OauthApiError(400, 'invalid_request', 'code_verifier is required.');
          // RFC 7636 §4.1 shape, then the match. A wrong verifier spends the code, so a code cannot
          // be ground against; a request that names no verifier at all leaves it for a retry.
          if (!isValidCodeVerifier(codeVerifier) || !pkceMatches(codeVerifier, authCode.code_challenge)) {
            ws.authCodes.delete(authCode.id);
            throw new OauthApiError(400, 'invalid_grant', 'The authorization code has expired or is invalid.');
          }
        } else if (isPublicClient(application)) {
          throw new OauthApiError(400, 'invalid_grant', 'The authorization code has expired or is invalid.');
        }

        const granted = narrowScope(authCode.connect.scope, scope);
        const bound = bindResource(authCode.connect.resource, resource);
        const user = ws.users.get(authCode.user_id)!;

        // Same organization rule as the authenticate grant: the code's own organization when the
        // sign-in chose one and the membership still stands, else the user's only one. A user in
        // several who chose none gets an unscoped token — there is no page to ask on this hop.
        let organizationId = authCode.organization_id;
        const organizations = activeOrganizationsFor(ws, user.id);
        if (organizationId && !organizations.some((o) => o.id === organizationId)) {
          throw new OauthApiError(400, 'invalid_grant', 'The authorization code has expired or is invalid.');
        }
        if (!organizationId && organizations.length === 1) organizationId = organizations[0].id;

        ws.authCodes.delete(authCode.id);
        const session = startSession(c, user, organizationId, authCode);
        response = issueUserTokens(application, session, granted, bound);
      } else {
        // Minimal Standalone Connect exchange: no refresh token, id_token, or PKCE.
        const granted = narrowScope(Array.isArray(application.scopes) ? application.scopes : [], scope);
        response = {
          access_token: jwt.sign(
            {
              sub: authCode.user_id,
              aud: application.audience ?? application.client_id,
              jti: generateUlid(),
              org_id: application.organization_id ?? undefined,
              scope: granted.join(' '),
            },
            { expiresIn: TOKEN_TTL_SECONDS },
          ),
          token_type: 'Bearer',
          expires_in: TOKEN_TTL_SECONDS,
          scope: granted.join(' '),
        };
        ws.authCodes.delete(authCode.id);
      }
    } else {
      // Grant the requested scopes, defaulting to all of the application's scopes. A
      // request may narrow to a subset (space-delimited, per RFC 6749 §3.3); requesting
      // a scope the application does not have is rejected so authz logic can be tested.
      // Guard against a malformed (non-array) stored scopes value so a request never
      // substring-matches a scope string or hits a .join on a non-array.
      const granted = narrowScope(Array.isArray(application.scopes) ? application.scopes : [], scope);

      // Both the audience and tenant come from the stored application, never the caller,
      // so a client can't mint a token for an arbitrary aud or an org it isn't tied to.
      // aud defaults to the client_id; pin `audience` on the app to match production.
      response = {
        access_token: jwt.sign(
          {
            sub: application.client_id,
            aud: application.audience ?? application.client_id,
            jti: generateUlid(),
            org_id: application.organization_id ?? undefined,
            scope: granted.join(' '),
          },
          { expiresIn: TOKEN_TTL_SECONDS },
        ),
        token_type: 'Bearer',
        expires_in: TOKEN_TTL_SECONDS,
        scope: granted.join(' '),
      };
    }

    // Stamped only once the exchange has actually produced a token — a secret presented on a
    // request that then fails on grant type, code or scope was never used to get one. Silent,
    // because presenting a secret is not an edit to it, so `updated_at` stays put.
    if (matchedSecret) ws.clientSecrets.updateSilent(matchedSecret.id, { last_used_at: new Date().toISOString() });

    // RFC 6749 §5.1: a response carrying tokens is not to be cached.
    return c.json(response, 200, { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  });

  // The M2M authorization server's JWKS. Same signing key as /sso/jwks/:client_id, so a
  // service pointed at the authoritative server's well-known JWKS validates M2M tokens.
  app.get('/oauth2/jwks', (c) => c.json(jwt.getJWKS()));
}
