/**
 * The AuthKit domain as an OAuth 2.1 authorization server: `/oauth2/authorize` on an application
 * with no `login_url`, and `/oauth2/token` for the codes and refresh tokens that leads to. The
 * `client_credentials` and Standalone Connect halves of the same endpoints are covered by
 * oauth.spec.ts and standalone-connect.spec.ts.
 */
import { createHash, randomBytes } from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { createServer } from '../../core/index.js';
import { createEmulator, type Emulator } from '../../index.js';
import { seedFromConfig, workosPlugin } from '../index.js';
import { getWorkOSStore } from '../store.js';

const baseUrl = 'http://localhost:4100';
const callback = 'http://localhost:33418/callback';
const json = (res: Response) => res.json() as Promise<any>;
const decode = (token: string) =>
  JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf-8')) as Record<string, any>;

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

function createTestApp() {
  const server = createServer(workosPlugin, {
    port: 0,
    baseUrl,
    apiKeys: { sk_test_default: { environment: 'test' } },
  });
  seedFromConfig(server.store, baseUrl, {
    users: [{ email: 'alice@acme.test', first_name: 'Alice' }, { email: 'bob@other.test' }],
    organizations: [{ name: 'Acme', memberships: [{ email: 'alice@acme.test' }] }],
    resourceIndicators: [{ uri: 'https://mcp.example.test' }],
  });
  return server;
}

describe('AuthKit OAuth server', () => {
  let server: ReturnType<typeof createTestApp>;
  let ws: ReturnType<typeof getWorkOSStore>;

  beforeEach(() => {
    server = createTestApp();
    ws = getWorkOSStore(server.store);
  });

  const request = (path: string, init?: RequestInit) => server.app.request(path, init);

  /** Register a client the way an MCP client does, returning what it would hold. */
  const register = async (extra: Record<string, unknown> = {}) => {
    const res = await request('/oauth2/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [callback],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        ...extra,
      }),
    });
    expect(res.status).toBe(201);
    return (await json(res)) as { client_id: string; client_secret?: string };
  };

  const authorizeUrl = (params: Record<string, string>) =>
    `/oauth2/authorize?${new URLSearchParams({ response_type: 'code', redirect_uri: callback, ...params })}`;

  /**
   * Follow authorize through the hosted sign-in, without interactive mode, to the callback. Returns
   * the final redirect, which carries either a code or an error.
   */
  const signIn = async (params: Record<string, string>) => {
    const authorize = await request(authorizeUrl(params));
    expect(authorize.status).toBe(302);
    const location = new URL(authorize.headers.get('location')!);
    if (location.pathname !== '/user_management/authorize') return { authorize, callback: location };
    const hosted = await request(`${location.pathname}${location.search}`);
    expect(hosted.status).toBe(302);
    return { authorize, callback: new URL(hosted.headers.get('location')!) };
  };

  const authorizeCode = async (client_id: string, extra: Record<string, string> = {}) => {
    const { verifier, challenge } = pkce();
    const { callback: url } = await signIn({
      client_id,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'xyz',
      login_hint: 'alice@acme.test',
      ...extra,
    });
    expect(url.searchParams.get('error')).toBeNull();
    expect(url.searchParams.get('state')).toBe('xyz');
    return { code: url.searchParams.get('code')!, verifier };
  };

  const token = (body: Record<string, string>, headers: Record<string, string> = {}) =>
    request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString(),
    });

  const exchange = async (
    client_id: string,
    extra: Record<string, string> = {},
    authorize: Record<string, string> = {},
  ) => {
    const { code, verifier } = await authorizeCode(client_id, authorize);
    return token({
      grant_type: 'authorization_code',
      client_id,
      code,
      redirect_uri: callback,
      code_verifier: verifier,
      ...extra,
    });
  };

  describe('authorize', () => {
    it('sends the browser to the hosted sign-in, which completes with a code and the state', async () => {
      const { client_id } = await register();
      const { challenge } = pkce();
      const authorize = await request(
        authorizeUrl({ client_id, code_challenge: challenge, code_challenge_method: 'S256', state: 's t/a?te' }),
      );
      expect(authorize.status).toBe(302);
      const signInUrl = new URL(authorize.headers.get('location')!);
      expect(signInUrl.pathname).toBe('/user_management/authorize');
      expect(signInUrl.searchParams.get('connect_request')).toMatch(/^connect_req_/);
      // The request itself is parked server-side; nothing a caller could tamper with rides the URL.
      expect(signInUrl.searchParams.has('redirect_uri')).toBe(false);
      expect(signInUrl.searchParams.has('code_challenge')).toBe(false);

      const hosted = await request(`${signInUrl.pathname}${signInUrl.search}`);
      expect(hosted.status).toBe(302);
      const done = new URL(hosted.headers.get('location')!);
      expect(`${done.origin}${done.pathname}`).toBe(callback);
      expect(done.searchParams.get('code')).toMatch(/^auth_code_/);
      expect(done.searchParams.get('state')).toBe('s t/a?te');
      // Spent with the code it produced.
      expect(
        server.store.getData(`connect_authorize:${signInUrl.searchParams.get('connect_request')}`),
      ).toBeUndefined();
    });

    it('answers an unknown client with a redirect to the error page, which is served', async () => {
      const res = await request(authorizeUrl({ client_id: 'client_nope' }));
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location')!);
      expect(location.pathname).toBe('/oauth2/error');
      expect(location.searchParams.get('error')).toBe('application_not_found');
      const page = await request(`${location.pathname}${location.search}`);
      expect(page.status).toBe(200);
      expect(page.headers.get('content-type')).toContain('text/html');
      expect(await page.text()).toContain('Application not found');
    });

    it('keeps the plain errors for what it cannot report on a callback', async () => {
      const { client_id } = await register();
      const invalid: Record<string, string>[] = [
        { client_id: '' },
        { client_id, redirect_uri: '' },
        { client_id, response_type: 'token' },
        { client_id, redirect_uri: 'http://localhost:33418/other' },
      ];
      for (const params of invalid) {
        const res = await request(authorizeUrl(params));
        expect(res.status).toBe(400);
      }
      const m2m = ws.connectApplications.insert({
        object: 'connect_application',
        name: 'svc',
        description: null,
        application_type: 'm2m',
        organization_id: null,
        scopes: [],
        audience: null,
        redirect_uris: [],
        is_first_party: true,
        was_dynamically_registered: false,
        uses_pkce: false,
        login_url: null,
        client_id: 'client_m2m',
        logo_url: null,
      });
      expect(m2m.application_type).toBe('m2m');
      expect((await request(authorizeUrl({ client_id: 'client_m2m' }))).status).toBe(400);
    });

    it('requires PKCE of a public client, reporting it on the callback with the state', async () => {
      const { client_id } = await register();
      const { callback: url } = await signIn({ client_id, state: 'keep' });
      expect(`${url.origin}${url.pathname}`).toBe(callback);
      expect(url.searchParams.get('error')).toBe('invalid_request');
      expect(url.searchParams.get('error_description')).toContain('code_challenge is required');
      expect(url.searchParams.get('state')).toBe('keep');
    });

    it('does not require PKCE of a confidential client, but validates it when sent', async () => {
      const { client_id } = await register({ token_endpoint_auth_method: 'client_secret_basic' });
      const { callback: ok } = await signIn({ client_id, login_hint: 'alice@acme.test' });
      expect(ok.searchParams.get('code')).toMatch(/^auth_code_/);
      const bad = await signIn({ client_id, code_challenge: 'short', code_challenge_method: 'S256' });
      expect(bad.callback.searchParams.get('error')).toBe('invalid_request');
    });

    it('supports only S256', async () => {
      const { client_id } = await register();
      const { challenge } = pkce();
      const plain = await signIn({ client_id, code_challenge: challenge, code_challenge_method: 'plain' });
      expect(plain.callback.searchParams.get('error')).toBe('invalid_request');
      const orphan = await signIn({ client_id, code_challenge_method: 'S256' });
      expect(orphan.callback.searchParams.get('error')).toBe('invalid_request');
    });

    it('reports invalid_scope and invalid_target on the callback', async () => {
      const { client_id } = await register({ scope: 'openid profile' });
      const { challenge } = pkce();
      const base = { client_id, code_challenge: challenge, code_challenge_method: 'S256' };
      const scope = await signIn({ ...base, scope: 'openid email' });
      expect(scope.callback.searchParams.get('error')).toBe('invalid_scope');
      const target = await signIn({ ...base, resource: 'https://mcp.example.test/#frag' });
      expect(target.callback.searchParams.get('error')).toBe('invalid_target');
      const relative = await signIn({ ...base, resource: 'mcp/relative' });
      expect(relative.callback.searchParams.get('error')).toBe('invalid_target');
    });

    it('rejects a hosted sign-in whose request has expired or never existed', async () => {
      const { client_id } = await register();
      const { challenge } = pkce();
      const authorize = await request(authorizeUrl({ client_id, code_challenge: challenge }));
      const signInUrl = new URL(authorize.headers.get('location')!);
      const key = `connect_authorize:${signInUrl.searchParams.get('connect_request')}`;
      const stored = server.store.getData<any>(key);
      server.store.setData(key, { ...stored, expires_at: new Date(Date.now() - 1000).toISOString() });
      const expired = await request(`${signInUrl.pathname}${signInUrl.search}`);
      expect(expired.status).toBe(400);
      expect((await json(expired)).error).toBe('invalid_request');
      const unknown = await request('/user_management/authorize?connect_request=connect_req_nope');
      expect(unknown.status).toBe(400);
    });

    it('signs in the user named by login_hint and honors organization_id', async () => {
      const { client_id } = await register();
      const { code } = await authorizeCode(client_id, { login_hint: 'bob@other.test' });
      expect(ws.authCodes.findOneBy('code', code)!.user_id).toBe(ws.users.findOneBy('email', 'bob@other.test')!.id);
      const acme = ws.organizations.findOneBy('name', 'Acme')!;
      const scoped = await authorizeCode(client_id, { organization_id: acme.id });
      expect(ws.authCodes.findOneBy('code', scoped.code)!.organization_id).toBe(acme.id);
      // Not a member: the same refusal /user_management/authorize gives.
      const { challenge } = pkce();
      const res = await request(
        authorizeUrl({ client_id, code_challenge: challenge, login_hint: 'bob@other.test', organization_id: acme.id }),
      );
      const followed = await request(
        new URL(res.headers.get('location')!).pathname + new URL(res.headers.get('location')!).search,
      );
      expect(followed.status).toBe(400);
    });
  });

  describe('token: authorization_code', () => {
    it('lets a public client redeem a code with its verifier alone', async () => {
      const { client_id } = await register();
      const res = await exchange(client_id, {}, { scope: 'openid profile', resource: 'https://mcp.example.test' });
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 3600, scope: 'openid profile' });
      expect(body.access_token.split('.')).toHaveLength(3);
      expect(body.refresh_token).toMatch(/^ref_/);
    });

    it('mints a Connect token: bare issuer, no email, the claims production carries', async () => {
      const { client_id } = await register();
      const alice = ws.users.findOneBy('email', 'alice@acme.test')!;
      const acme = ws.organizations.findOneBy('name', 'Acme')!;
      const body = await json(await exchange(client_id, {}, { scope: 'openid email' }));

      const claims = server.jwt.verify(body.access_token);
      expect(claims.iss).toBe(baseUrl);
      expect(claims.sub).toBe(alice.id);
      expect(claims.client_id).toBe(client_id);
      expect(claims.org_id).toBe(acme.id);
      expect(claims.scope).toBe('openid email');
      expect(claims.sid).toMatch(/^session_/);
      expect(claims.jti).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
      expect(claims.exp - claims.iat).toBe(3600);
      expect(claims.aud).toBe(client_id);
      for (const absent of ['email', 'role', 'permissions', 'entitlements']) expect(claims).not.toHaveProperty(absent);

      // The session the token names is a real, active one for that user.
      const session = ws.sessions.get(claims.sid as string)!;
      expect(session).toMatchObject({ user_id: alice.id, status: 'active', organization_id: acme.id });
    });

    it('omits org_id for a user with no organization', async () => {
      const { client_id } = await register();
      const { code, verifier } = await authorizeCode(client_id, { login_hint: 'bob@other.test' });
      const body = await json(
        await token({
          grant_type: 'authorization_code',
          client_id,
          code,
          redirect_uri: callback,
          code_verifier: verifier,
        }),
      );
      expect(server.jwt.verify(body.access_token)).not.toHaveProperty('org_id');
    });

    it('defaults the scope to the application scopes', async () => {
      const { client_id } = await register({ scope: 'openid profile' });
      const body = await json(await exchange(client_id));
      expect(body.scope).toBe('openid profile');
    });

    it('leaves the code for a retry when no verifier is sent, but spends it on a wrong one', async () => {
      const { client_id } = await register();
      const first = await authorizeCode(client_id);
      const grant = { grant_type: 'authorization_code', client_id, code: first.code, redirect_uri: callback };

      const missing = await token(grant);
      expect(missing.status).toBe(400);
      expect((await json(missing)).error).toBe('invalid_request');
      expect((await token({ ...grant, code_verifier: first.verifier })).status).toBe(200);

      // A wrong verifier is a failed attempt, and the code is gone even for the right one afterwards.
      const second = await authorizeCode(client_id);
      const attempt = { ...grant, code: second.code };
      const wrong = await token({ ...attempt, code_verifier: pkce().verifier });
      expect(wrong.status).toBe(400);
      expect((await json(wrong)).error).toBe('invalid_grant');
      expect((await json(await token({ ...attempt, code_verifier: second.verifier }))).error).toBe('invalid_grant');
    });

    it('enforces the RFC 7636 §4.1 verifier shape, spending the code when it is malformed', async () => {
      const { client_id } = await register();
      for (const bad of ['short', 'a'.repeat(129), `${'a'.repeat(42)}!`, `${'a'.repeat(42)} `]) {
        const { code } = await authorizeCode(client_id);
        const res = await token({
          grant_type: 'authorization_code',
          client_id,
          code,
          redirect_uri: callback,
          code_verifier: bad,
        });
        expect(res.status).toBe(400);
        expect((await json(res)).error).toBe('invalid_grant');
        expect(ws.authCodes.findOneBy('code', code)).toBeUndefined();
      }
      // The boundaries are valid: 43 and 128 characters of the unreserved set.
      for (const verifier of ['A'.repeat(43), 'a-._~9'.repeat(21) + 'ab']) {
        const challenge = createHash('sha256').update(verifier).digest('base64url');
        const { callback: url } = await signIn({
          client_id,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          login_hint: 'alice@acme.test',
        });
        const res = await token({
          grant_type: 'authorization_code',
          client_id,
          code: url.searchParams.get('code')!,
          redirect_uri: callback,
          code_verifier: verifier,
        });
        expect(res.status).toBe(200);
      }
    });

    it('marks token responses uncacheable (RFC 6749 §5.1)', async () => {
      const { client_id } = await register();
      const res = await exchange(client_id);
      expect(res.status).toBe(200);
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(res.headers.get('pragma')).toBe('no-cache');
      const refreshed = await token({
        grant_type: 'refresh_token',
        client_id,
        refresh_token: (await json(res)).refresh_token,
      });
      expect(refreshed.headers.get('cache-control')).toBe('no-store');
      expect(refreshed.headers.get('pragma')).toBe('no-cache');
    });

    it('rejects a reused code', async () => {
      const { client_id } = await register();
      const { code, verifier } = await authorizeCode(client_id);
      const grant = {
        grant_type: 'authorization_code',
        client_id,
        code,
        redirect_uri: callback,
        code_verifier: verifier,
      };
      expect((await token(grant)).status).toBe(200);
      const again = await token(grant);
      expect(again.status).toBe(400);
      expect((await json(again)).error).toBe('invalid_grant');
    });

    it('rejects a wrong redirect_uri, another client, an expired code and an unknown code', async () => {
      const { client_id } = await register();
      const other = await register();
      const { code, verifier } = await authorizeCode(client_id);
      const grant = {
        grant_type: 'authorization_code',
        client_id,
        code,
        redirect_uri: callback,
        code_verifier: verifier,
      };

      for (const override of [
        { redirect_uri: 'http://localhost:33418/other' },
        { client_id: other.client_id },
        { code: 'auth_code_unknown' },
      ]) {
        const res = await token({ ...grant, ...override });
        expect(res.status).toBe(400);
        expect((await json(res)).error).toBe('invalid_grant');
      }
      const stored = ws.authCodes.findOneBy('code', code)!;
      ws.authCodes.update(stored.id, { expires_at: new Date(Date.now() - 1000).toISOString() });
      expect((await json(await token(grant))).error).toBe('invalid_grant');
    });

    it('refuses a public client a code that carries no challenge', async () => {
      const { client_id } = await register();
      const { code } = await authorizeCode(client_id);
      const stored = ws.authCodes.findOneBy('code', code)!;
      ws.authCodes.update(stored.id, { code_challenge: null, code_challenge_method: null });
      const res = await token({ grant_type: 'authorization_code', client_id, code, redirect_uri: callback });
      expect((await json(res)).error).toBe('invalid_grant');
    });

    it('requires the secret of a confidential client, in the way it registered, and still checks PKCE', async () => {
      const { client_id, client_secret } = await register({ token_endpoint_auth_method: 'client_secret_basic' });
      const { code, verifier } = await authorizeCode(client_id);
      const grant = { grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier };

      const noSecret = await token({ ...grant, client_id });
      expect(noSecret.status).toBe(401);
      expect((await json(noSecret)).error_description).toBe('Missing authorization header.');
      const wrong = await token({ ...grant, client_id, client_secret: 'secret_wrong' });
      expect(wrong.status).toBe(401);
      expect((await json(wrong)).error).toBe('invalid_client');
      // Registered for Basic, so the right secret in the body is refused too.
      const viaPost = await token({ ...grant, client_id, client_secret: client_secret! });
      expect(viaPost.status).toBe(401);
      expect(viaPost.headers.get('www-authenticate')).toBe('Basic realm="AuthKit"');
      const basic = Buffer.from(`${client_id}:${client_secret}`).toString('base64');
      const badVerifier = await token(
        { ...grant, code_verifier: pkce().verifier },
        { Authorization: `Basic ${basic}` },
      );
      expect((await json(badVerifier)).error).toBe('invalid_grant');

      // That failed attempt spent the code; a fresh one redeems with Basic.
      const fresh = await authorizeCode(client_id);
      const ok = await token(
        { ...grant, code: fresh.code, code_verifier: fresh.verifier },
        { Authorization: `Basic ${basic}` },
      );
      expect(ok.status).toBe(200);
      const stored = ws.clientSecrets.all().find((s) => s.value === client_secret)!;
      expect(stored.last_used_at).not.toBeNull();
    });

    it('accepts client_secret_post only for a client registered for it', async () => {
      const { client_id, client_secret } = await register({ token_endpoint_auth_method: 'client_secret_post' });
      const first = await authorizeCode(client_id);
      const grant = { grant_type: 'authorization_code', client_id, redirect_uri: callback };
      const basic = Buffer.from(`${client_id}:${client_secret}`).toString('base64');
      const viaBasic = await token(
        { ...grant, code: first.code, code_verifier: first.verifier },
        { Authorization: `Basic ${basic}` },
      );
      expect(viaBasic.status).toBe(401);
      const viaPost = await token({
        ...grant,
        code: first.code,
        code_verifier: first.verifier,
        client_secret: client_secret!,
      });
      expect(viaPost.status).toBe(200);
    });

    it('holds a public client that presents a secret to it', async () => {
      const { client_id } = await register();
      const { code, verifier } = await authorizeCode(client_id);
      const res = await token({
        grant_type: 'authorization_code',
        client_id,
        client_secret: 'secret_made_up',
        code,
        redirect_uri: callback,
        code_verifier: verifier,
      });
      expect(res.status).toBe(401);
    });

    it('answers a request with no client at all as production does', async () => {
      const res = await token({ grant_type: 'authorization_code', code: 'x', redirect_uri: callback });
      expect(res.status).toBe(401);
      expect(await json(res)).toEqual({ error: 'invalid_client', error_description: 'Missing authorization header.' });
    });

    it('answers an unknown client_id with invalid_client, secret or not', async () => {
      const res = await token({
        grant_type: 'authorization_code',
        client_id: 'client_nope',
        code: 'x',
        redirect_uri: callback,
      });
      expect(res.status).toBe(401);
      expect((await json(res)).error).toBe('invalid_client');
    });

    it('keeps the codes of the two token endpoints apart', async () => {
      const { client_id } = await register();
      const { code, verifier } = await authorizeCode(client_id);
      // A hosted-sign-in code is not redeemable by /user_management/authenticate…
      const viaAuthenticate = await request('/user_management/authenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'authorization_code', client_id, code, code_verifier: verifier }),
      });
      expect(viaAuthenticate.status).toBe(400);
      expect((await json(viaAuthenticate)).error).toBe('invalid_grant');
      // …and was not spent by the attempt.
      expect(
        (
          await token({
            grant_type: 'authorization_code',
            client_id,
            code,
            redirect_uri: callback,
            code_verifier: verifier,
          })
        ).status,
      ).toBe(200);

      // An AuthKit code from /user_management/authorize is not redeemable here.
      const authKit = await request(
        `/user_management/authorize?${new URLSearchParams({ redirect_uri: callback, client_id })}`,
      );
      const authKitCode = new URL(authKit.headers.get('location')!).searchParams.get('code')!;
      const res = await token({
        grant_type: 'authorization_code',
        client_id,
        code: authKitCode,
        redirect_uri: callback,
      });
      expect((await json(res)).error).toBe('invalid_grant');
    });

    it('does not let a public application redeem a Standalone Connect code without its secret', async () => {
      seedFromConfig(server.store, baseUrl, {
        connectApplications: [
          {
            name: 'Standalone',
            type: 'oauth',
            uses_pkce: true,
            client_id: 'client_standalone_pkce',
            client_secret: 'secret_standalone_pkce',
            login_url: 'http://localhost:3000/login',
            redirect_uris: [callback],
          },
        ],
      });
      const alice = ws.users.findOneBy('email', 'alice@acme.test')!;
      const code = ws.authCodes.insert({
        user_id: alice.id,
        organization_id: null,
        code: 'auth_code_standalone',
        redirect_uri: callback,
        client_id: 'client_standalone_pkce',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        auth_method: 'external_auth',
        step_up_method: null,
        code_challenge: null,
        code_challenge_method: null,
      });
      const grant = {
        grant_type: 'authorization_code',
        client_id: 'client_standalone_pkce',
        code: code.code,
        redirect_uri: callback,
      };
      expect((await token(grant)).status).toBe(400);
      expect((await token({ ...grant, client_secret: 'secret_standalone_pkce' })).status).toBe(200);
    });

    it('refuses client_credentials to a public client without a secret', async () => {
      const { client_id } = await register();
      const res = await token({ grant_type: 'client_credentials', client_id });
      expect(res.status).toBe(401);
      expect((await json(res)).error).toBe('invalid_client');
    });

    it('narrows scope at exchange but never widens it', async () => {
      const { client_id } = await register();
      const narrowed = await json(await exchange(client_id, { scope: 'openid' }, { scope: 'openid profile' }));
      expect(narrowed.scope).toBe('openid');
      const widened = await exchange(client_id, { scope: 'openid email' }, { scope: 'openid profile' });
      expect(widened.status).toBe(400);
      expect((await json(widened)).error).toBe('invalid_scope');
    });
  });

  describe('resource indicators', () => {
    it('binds aud to a registered resource', async () => {
      const { client_id } = await register();
      const body = await json(await exchange(client_id, {}, { resource: 'https://mcp.example.test' }));
      expect(server.jwt.verify(body.access_token).aud).toBe('https://mcp.example.test');
    });

    it('falls back to the application audience, then the client_id, for an unregistered or absent resource', async () => {
      const { client_id } = await register();
      const unregistered = await json(
        await exchange(client_id, {}, { resource: 'https://not-registered.example.test' }),
      );
      expect(server.jwt.verify(unregistered.access_token).aud).toBe(client_id);
      const absent = await json(await exchange(client_id));
      expect(server.jwt.verify(absent.access_token).aud).toBe(client_id);

      const application = ws.connectApplications.findOneBy('client_id', client_id)!;
      ws.connectApplications.update(application.id, { audience: 'https://default-audience.example.test' });
      const withAudience = await json(
        await exchange(client_id, {}, { resource: 'https://not-registered.example.test' }),
      );
      expect(server.jwt.verify(withAudience.access_token).aud).toBe('https://default-audience.example.test');
      // A registered resource still wins over the application's audience.
      const registered = await json(await exchange(client_id, {}, { resource: 'https://mcp.example.test' }));
      expect(server.jwt.verify(registered.access_token).aud).toBe('https://mcp.example.test');
    });

    it('lets the token request restate or omit the authorized resource, and nothing else', async () => {
      const { client_id } = await register();
      const restated = await exchange(
        client_id,
        { resource: 'https://mcp.example.test' },
        { resource: 'https://mcp.example.test' },
      );
      expect(server.jwt.verify((await json(restated)).access_token).aud).toBe('https://mcp.example.test');

      const mismatch = await exchange(
        client_id,
        { resource: 'https://other.example.test' },
        { resource: 'https://mcp.example.test' },
      );
      expect(mismatch.status).toBe(400);
      expect((await json(mismatch)).error).toBe('invalid_target');
      const malformed = await exchange(client_id, { resource: 'not a uri' });
      expect((await json(malformed)).error).toBe('invalid_target');

      // A grant authorized for no resource cannot pick one up at the token endpoint, registered or not.
      for (const resource of ['https://mcp.example.test', 'https://other.example.test']) {
        const late = await exchange(client_id, { resource });
        expect(late.status).toBe(400);
        expect((await json(late)).error).toBe('invalid_target');
      }
      const plain = await json(await exchange(client_id));
      expect(server.jwt.verify(plain.access_token).aud).toBe(client_id);
    });

    it('restates the authorized resource harmlessly at the token endpoint', async () => {
      const { client_id } = await register();
      const res = await exchange(
        client_id,
        { resource: 'https://mcp.example.test' },
        { resource: 'https://mcp.example.test' },
      );
      expect(server.jwt.verify((await json(res)).access_token).aud).toBe('https://mcp.example.test');
    });
  });

  describe('token: refresh_token', () => {
    const refresh = (client_id: string, refresh_token: string, extra: Record<string, string> = {}) =>
      token({ grant_type: 'refresh_token', client_id, refresh_token, ...extra });

    it('rotates the token within the same session and carries scope and resource across', async () => {
      const { client_id } = await register();
      const first = await json(
        await exchange(client_id, {}, { scope: 'openid profile', resource: 'https://mcp.example.test' }),
      );

      const res = await refresh(client_id, first.refresh_token);
      expect(res.status).toBe(200);
      const second = await json(res);
      expect(second.refresh_token).toMatch(/^ref_/);
      expect(second.refresh_token).not.toBe(first.refresh_token);
      expect(second.scope).toBe('openid profile');

      const before = server.jwt.verify(first.access_token);
      const after = server.jwt.verify(second.access_token);
      expect(after.sid).toBe(before.sid);
      expect(after.sub).toBe(before.sub);
      expect(after.iss).toBe(baseUrl);
      expect(after.client_id).toBe(client_id);
      expect(after.aud).toBe('https://mcp.example.test');
      expect(after.org_id).toBe(before.org_id);
      expect(after.jti).not.toBe(before.jti);
      expect(ws.sessions.all().filter((s) => s.user_id === before.sub)).toHaveLength(1);

      // The old token is spent; the new one rotates again.
      const reused = await refresh(client_id, first.refresh_token);
      expect(reused.status).toBe(400);
      expect((await json(reused)).error).toBe('invalid_grant');
      expect((await refresh(client_id, second.refresh_token)).status).toBe(200);
    });

    it('narrows scope on refresh, and the narrowing sticks', async () => {
      const { client_id } = await register();
      const first = await json(await exchange(client_id, {}, { scope: 'openid profile email' }));
      const narrowed = await json(await refresh(client_id, first.refresh_token, { scope: 'openid' }));
      expect(narrowed.scope).toBe('openid');
      const widened = await refresh(client_id, narrowed.refresh_token, { scope: 'openid profile' });
      expect(widened.status).toBe(400);
      expect((await json(widened)).error).toBe('invalid_scope');
    });

    it('does not spend the token on a request it refuses', async () => {
      const { client_id } = await register();
      const first = await json(await exchange(client_id, {}, { resource: 'https://mcp.example.test' }));
      expect((await refresh(client_id, first.refresh_token, { scope: 'admin' })).status).toBe(400);
      expect((await refresh(client_id, first.refresh_token, { resource: 'https://other.example.test' })).status).toBe(
        400,
      );
      expect((await refresh(client_id, first.refresh_token)).status).toBe(200);
    });

    it('falls back on the next mint when the bound resource is deleted', async () => {
      const { client_id } = await register();
      const first = await json(await exchange(client_id, {}, { resource: 'https://mcp.example.test' }));
      const resource = ws.authkitOauthResources.findOneBy('uri', 'https://mcp.example.test')!;
      ws.authkitOauthResources.delete(resource.id);
      const second = await json(await refresh(client_id, first.refresh_token));
      expect(server.jwt.verify(second.access_token).aud).toBe(client_id);
    });

    it('is bound to the client it was issued to', async () => {
      const { client_id } = await register();
      const other = await register();
      const first = await json(await exchange(client_id));
      const res = await refresh(other.client_id, first.refresh_token);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('invalid_grant');
      // Refused, not spent.
      expect((await refresh(client_id, first.refresh_token)).status).toBe(200);
    });

    it('rejects unknown, expired, and revoked-session refresh tokens', async () => {
      const { client_id } = await register();
      expect((await json(await refresh(client_id, 'ref_unknown'))).error).toBe('invalid_grant');
      expect((await json(await token({ grant_type: 'refresh_token', client_id }))).error).toBe('invalid_request');

      const first = await json(await exchange(client_id));
      const stored = ws.refreshTokens.findOneBy('token', first.refresh_token)!;
      ws.refreshTokens.update(stored.id, { expires_at: new Date(Date.now() - 1000).toISOString() });
      const expired = await refresh(client_id, first.refresh_token);
      expect((await json(expired)).error_description).toBe('Refresh token has expired.');

      const second = await json(await exchange(client_id));
      const sid = server.jwt.verify(second.access_token).sid as string;
      ws.sessions.update(sid, { status: 'revoked', ended_at: new Date().toISOString() });
      expect((await json(await refresh(client_id, second.refresh_token))).error).toBe('invalid_grant');
    });

    it('is not accepted by, and does not accept, the AuthKit refresh grant', async () => {
      const { client_id } = await register();
      const first = await json(await exchange(client_id));
      const viaAuthenticate = await request('/user_management/authenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'refresh_token', client_id, refresh_token: first.refresh_token }),
      });
      expect((await json(viaAuthenticate)).error).toBe('invalid_grant');
      expect((await refresh(client_id, first.refresh_token)).status).toBe(200);

      // A refresh token AuthKit's own grant issued carries no Connect marker, so this endpoint refuses it.
      const alice = ws.users.findOneBy('email', 'alice@acme.test')!;
      const stray = ws.refreshTokens.insert({
        token: 'ref_authkit',
        user_id: alice.id,
        organization_id: null,
        session_id: 'session_x',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        client_id,
      });
      expect(stray.connect).toBeUndefined();
      expect((await json(await refresh(client_id, 'ref_authkit'))).error).toBe('invalid_grant');
    });
  });

  describe('surfaces that must not change', () => {
    it('still serves client_credentials for a seeded m2m application', async () => {
      seedFromConfig(server.store, baseUrl, {
        organizations: [{ name: 'Svc' }],
        connectApplications: [
          {
            name: 'Svc',
            type: 'm2m',
            organization: 'Svc',
            client_id: 'client_svc',
            client_secret: 'secret_svc',
            scopes: ['a'],
          },
        ],
      });
      const res = await token({
        grant_type: 'client_credentials',
        client_id: 'client_svc',
        client_secret: 'secret_svc',
      });
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body).not.toHaveProperty('refresh_token');
      expect(server.jwt.verify(body.access_token)).toMatchObject({ sub: 'client_svc', aud: 'client_svc', scope: 'a' });
    });

    it("leaves AuthKit's own per-client issuer and authorization_code grant unchanged", async () => {
      const res = await request(
        `/user_management/authorize?${new URLSearchParams({ redirect_uri: callback, client_id: 'client_authkit', login_hint: 'alice@acme.test' })}`,
      );
      const code = new URL(res.headers.get('location')!).searchParams.get('code')!;
      const auth = await json(
        await request('/user_management/authenticate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'client_authkit', code }),
        }),
      );
      expect(server.jwt.verify(auth.access_token).iss).toBe(`${baseUrl}/user_management/client_authkit`);
    });
  });
});

describe('AuthKit OAuth server, interactive hosted sign-in', () => {
  let emulator: Emulator | undefined;

  afterEach(async () => {
    await emulator?.close();
    emulator = undefined;
  });

  it('shows the AuthKit sign-in page and finishes the request from what authorize validated', async () => {
    emulator = await createEmulator({
      port: 0,
      interactiveAuth: true,
      seed: { users: [{ email: 'alice@acme.test' }] },
    });
    const reg = (await (
      await fetch(`${emulator.url}/oauth2/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [callback], token_endpoint_auth_method: 'none' }),
      })
    ).json()) as { client_id: string };
    const { verifier, challenge } = pkce();

    const authorize = await fetch(
      `${emulator.url}/oauth2/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: reg.client_id,
        redirect_uri: callback,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'st',
        resource: 'https://mcp.example.test',
      })}`,
      { redirect: 'manual' },
    );
    expect(authorize.status).toBe(302);
    const page = await fetch(authorize.headers.get('location')!, { redirect: 'manual' });
    expect(page.status).toBe(200);
    expect(page.headers.get('content-type')).toContain('text/html');
    const html = await page.text();
    expect(html).toContain('Sign In');
    expect(html).toContain('alice@acme.test');
    const requestId = new URL(authorize.headers.get('location')!).searchParams.get('connect_request')!;
    expect(html).toContain(`name="connect_request" value="${requestId}"`);

    // A submit that tries to swap the redirect, client or challenge gets the validated ones.
    const submit = await fetch(`${emulator.url}/user_management/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        connect_request: requestId,
        email: 'alice@acme.test',
        redirect_uri: 'http://localhost:9999/evil',
        client_id: 'client_evil',
        code_challenge: 'x'.repeat(43),
        state: 'evil',
      }),
    });
    expect(submit.status).toBe(302);
    const done = new URL(submit.headers.get('location')!);
    expect(`${done.origin}${done.pathname}`).toBe(callback);
    expect(done.searchParams.get('state')).toBe('st');

    const res = await fetch(`${emulator.url}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: reg.client_id,
        code: done.searchParams.get('code')!,
        redirect_uri: callback,
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    expect(decode(body.access_token)).toMatchObject({ client_id: reg.client_id, iss: emulator.url });

    // The request was spent by the code it minted: replaying the submit finds nothing.
    const replay = await fetch(`${emulator.url}/user_management/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ connect_request: requestId, email: 'alice@acme.test' }),
    });
    expect(replay.status).toBe(400);
  });
});

describe('AuthKit OAuth server, registered grant types and revoked grants', () => {
  let server: ReturnType<typeof createTestApp>;
  let ws: ReturnType<typeof getWorkOSStore>;

  beforeEach(() => {
    server = createTestApp();
    ws = getWorkOSStore(server.store);
  });

  const register = async (body: Record<string, unknown>) =>
    (await (
      await server.app.request('/oauth2/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [callback], token_endpoint_auth_method: 'none', ...body }),
      })
    ).json()) as { client_id: string };

  const codeFor = async (client_id: string, login_hint = 'alice@acme.test', extra: Record<string, string> = {}) => {
    const { verifier, challenge } = pkce();
    const authorize = await server.app.request(
      `/oauth2/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id,
        redirect_uri: callback,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        login_hint,
        ...extra,
      })}`,
    );
    const hosted = new URL(authorize.headers.get('location')!);
    const done = await server.app.request(`${hosted.pathname}${hosted.search}`);
    return { code: new URL(done.headers.get('location')!).searchParams.get('code')!, verifier };
  };

  const redeem = (client_id: string, code: string, verifier: string) =>
    server.app.request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id,
        code,
        redirect_uri: callback,
        code_verifier: verifier,
      }).toString(),
    });

  it('gives a client registered without refresh_token no refresh token, and refuses the grant', async () => {
    const { client_id } = await register({ grant_types: ['authorization_code'] });
    const { code, verifier } = await codeFor(client_id);
    const body = await json(await redeem(client_id, code, verifier));
    expect(body.access_token).toBeTruthy();
    expect(body).not.toHaveProperty('refresh_token');

    const refresh = await server.app.request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id, refresh_token: 'ref_any' }).toString(),
    });
    expect(refresh.status).toBe(400);
    expect((await json(refresh)).error).toBe('unauthorized_client');
  });

  it('refuses to register a client for refresh_token alone', async () => {
    const res = await server.app.request('/oauth2/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [callback], grant_types: ['refresh_token'] }),
    });
    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('invalid_client_metadata');
  });

  const apiHeaders = { Authorization: 'Bearer sk_test_default', 'Content-Type': 'application/json' };
  const both = ['authorization_code', 'refresh_token'];
  const refresh = (client_id: string, refresh_token: string, extra: Record<string, string> = {}) =>
    server.app.request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id, refresh_token, ...extra }).toString(),
    });
  const setScopes = async (client_id: string, scopes: string[]) => {
    const app = ws.connectApplications.findOneBy('client_id', client_id)!;
    const res = await server.app.request(`/connect/applications/${app.id}`, {
      method: 'PUT',
      headers: apiHeaders,
      body: JSON.stringify({ scopes }),
    });
    expect(res.status).toBe(200);
  };

  it('refuses a refresh for an organization the user has since left', async () => {
    for (const leave of ['deactivate', 'delete'] as const) {
      const { client_id } = await register({ grant_types: both });
      const acme = ws.organizations.findOneBy('name', 'Acme')!;
      const { code, verifier } = await codeFor(client_id, 'alice@acme.test', { organization_id: acme.id });
      const tokens = await json(await redeem(client_id, code, verifier));
      expect(server.jwt.verify(tokens.access_token).org_id).toBe(acme.id);

      const membership = ws.organizationMemberships.findBy(
        'user_id',
        ws.users.findOneBy('email', 'alice@acme.test')!.id,
      )[0];
      if (leave === 'delete') ws.organizationMemberships.delete(membership.id);
      else ws.organizationMemberships.update(membership.id, { status: 'inactive' });

      const res = await refresh(client_id, tokens.refresh_token);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('invalid_grant');
      if (leave === 'deactivate') ws.organizationMemberships.update(membership.id, { status: 'active' });
    }
  });

  it('does not re-issue a scope removed from the application, at exchange or at refresh', async () => {
    const { client_id } = await register({ grant_types: both, scope: 'openid profile email' });
    const first = await codeFor(client_id, 'alice@acme.test', { scope: 'openid profile email' });
    const tokens = await json(await redeem(client_id, first.code, first.verifier));
    expect(tokens.scope).toBe('openid profile email');

    await setScopes(client_id, ['openid', 'email']);
    const refreshed = await json(await refresh(client_id, tokens.refresh_token));
    expect(refreshed.scope).toBe('openid email');
    expect(server.jwt.verify(refreshed.access_token).scope).toBe('openid email');

    // At exchange: a code authorized before the removal.
    await setScopes(client_id, ['openid', 'profile', 'email']);
    const second = await codeFor(client_id, 'alice@acme.test', { scope: 'openid profile email' });
    await setScopes(client_id, ['email']);
    expect((await json(await redeem(client_id, second.code, second.verifier))).scope).toBe('email');
  });

  it('answers invalid_scope when no granted scope remains, at exchange and at refresh', async () => {
    const { client_id } = await register({ grant_types: both, scope: 'openid profile' });
    const first = await codeFor(client_id, 'alice@acme.test', { scope: 'openid' });
    const tokens = await json(await redeem(client_id, first.code, first.verifier));
    const pending = await codeFor(client_id, 'alice@acme.test', { scope: 'openid' });

    await setScopes(client_id, ['profile']);
    const atRefresh = await refresh(client_id, tokens.refresh_token);
    expect(atRefresh.status).toBe(400);
    expect((await json(atRefresh)).error).toBe('invalid_scope');
    const atExchange = await redeem(client_id, pending.code, pending.verifier);
    expect(atExchange.status).toBe(400);
    expect((await json(atExchange)).error).toBe('invalid_scope');
  });

  it('clearing a dynamic client’s scopes revokes pending and refresh grants without restoring standard scopes', async () => {
    const { client_id } = await register({ grant_types: both });
    const first = await codeFor(client_id);
    const tokens = await json(await redeem(client_id, first.code, first.verifier));
    expect(tokens.scope).toBe('email offline_access openid profile');
    const pending = await codeFor(client_id);

    const cleared = await server.app.request(`/connect/applications/${client_id}`, {
      method: 'PUT',
      headers: apiHeaders,
      body: JSON.stringify({ scopes: [] }),
    });
    expect(cleared.status).toBe(200);
    expect((await json(cleared)).scopes).toEqual([]);

    const atExchange = await redeem(client_id, pending.code, pending.verifier);
    const atRefresh = await refresh(client_id, tokens.refresh_token);
    const { challenge } = pkce();
    const authorize = await server.app.request(
      `/oauth2/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id,
        redirect_uri: callback,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        scope: 'email offline_access openid profile',
      })}`,
    );
    expect(authorize.status).toBe(302);
    const redirect = new URL(authorize.headers.get('location')!);

    // Omitting scope must fail before hosted sign-in rather than produce a code that cannot be exchanged.
    const omittedScope = await server.app.request(
      `/oauth2/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id,
        redirect_uri: callback,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      })}`,
    );
    expect(omittedScope.status).toBe(302);
    const omittedScopeRedirect = new URL(omittedScope.headers.get('location')!);
    expect({
      exchange: { status: atExchange.status, error: (await json(atExchange)).error },
      refresh: { status: atRefresh.status, error: (await json(atRefresh)).error },
      authorize: redirect.searchParams.get('error'),
      omittedScope: omittedScopeRedirect.searchParams.get('error'),
    }).toEqual({
      exchange: { status: 400, error: 'invalid_scope' },
      refresh: { status: 400, error: 'invalid_scope' },
      authorize: 'invalid_scope',
      omittedScope: 'invalid_scope',
    });
  });

  it('refuses a refresh once the session has expired', async () => {
    const { client_id } = await register({ grant_types: both });
    const { code, verifier } = await codeFor(client_id);
    const tokens = await json(await redeem(client_id, code, verifier));
    const sid = server.jwt.verify(tokens.access_token).sid as string;
    ws.sessions.update(sid, { expires_at: new Date(Date.now() - 1000).toISOString() });
    const res = await refresh(client_id, tokens.refresh_token);
    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('invalid_grant');
  });

  it('never lets a refresh token outlive its session', async () => {
    const { client_id } = await register({ grant_types: both });
    const { code, verifier } = await codeFor(client_id);
    const tokens = await json(await redeem(client_id, code, verifier));
    const sid = server.jwt.verify(tokens.access_token).sid as string;
    // The first token is issued with the session's own lifetime, so it is never longer.
    const session = ws.sessions.get(sid)!;
    expect(ws.refreshTokens.findOneBy('token', tokens.refresh_token)!.expires_at <= session.expires_at).toBe(true);

    const soon = new Date(Date.now() + 3600_000).toISOString();
    ws.sessions.update(sid, { expires_at: soon });
    const next = await json(await refresh(client_id, tokens.refresh_token));
    expect(ws.refreshTokens.findOneBy('token', next.refresh_token)!.expires_at).toBe(soon);
  });

  it('deleting the application removes its refresh tokens and parked authorize requests', async () => {
    const { client_id } = await register({ grant_types: both });
    const other = await register({ grant_types: both });
    const { code, verifier } = await codeFor(client_id);
    const tokens = await json(await redeem(client_id, code, verifier));
    const otherCode = await codeFor(other.client_id);
    const otherTokens = await json(await redeem(other.client_id, otherCode.code, otherCode.verifier));
    // A request parked by authorize and never finished, for each client.
    for (const id of [client_id, other.client_id]) {
      const { challenge } = pkce();
      await server.app.request(
        `/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: id, redirect_uri: callback, code_challenge: challenge })}`,
      );
    }
    const parked = (id: string) => {
      let n = 0;
      server.store.deleteDataByPrefix('connect_authorize:', (v: any) => {
        if (v.client_id === id) n++;
        return false;
      });
      return n;
    };
    expect(parked(client_id)).toBe(1);
    // An AuthKit refresh token that /user_management/authenticate stored under the same client_id.
    const authkit = ws.refreshTokens.insert({
      token: 'ref_authkit_same_client',
      user_id: ws.users.findOneBy('email', 'alice@acme.test')!.id,
      organization_id: null,
      session_id: 'session_authkit',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      client_id,
    });

    const app = ws.connectApplications.findOneBy('client_id', client_id)!;
    const del = await server.app.request(`/connect/applications/${app.id}`, { method: 'DELETE', headers: apiHeaders });
    expect(del.status).toBe(204);

    expect(ws.refreshTokens.findOneBy('token', tokens.refresh_token)).toBeUndefined();
    expect(parked(client_id)).toBe(0);
    expect((await json(await refresh(client_id, tokens.refresh_token))).error).toBe('invalid_client');
    // Another client's are untouched, and so is an AuthKit token that only shares the id.
    expect(ws.refreshTokens.findOneBy('token', otherTokens.refresh_token)).toBeDefined();
    expect(ws.refreshTokens.get(authkit.id)).toBeDefined();
    expect(parked(other.client_id)).toBe(1);
  });

  describe('id_token', () => {
    const claimsOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

    beforeEach(() => {
      const alice = ws.users.findOneBy('email', 'alice@acme.test')!;
      ws.users.update(alice.id, { name: 'Alice Smith', last_name: 'Smith', email_verified: true });
    });

    it('is issued at code exchange for the openid scope, signed under the JWKS key', async () => {
      const { client_id } = await register({ grant_types: both });
      const alice = ws.users.findOneBy('email', 'alice@acme.test')!;
      const first = await codeFor(client_id, 'alice@acme.test', { scope: 'openid', nonce: 'n-0S6_WzA2Mj' });
      const body = await json(await redeem(client_id, first.code, first.verifier));
      const header = JSON.parse(Buffer.from(body.id_token.split('.')[0], 'base64url').toString());
      expect(header.alg).toBe('RS256');
      expect(header.kid).toBe(server.jwt.getJWKS().keys[0].kid);
      // verify() checks the signature against the same key the JWKS publishes.
      const claims = server.jwt.verify(body.id_token);
      expect(claims).toMatchObject({ iss: baseUrl, sub: alice.id, aud: client_id, nonce: 'n-0S6_WzA2Mj' });
      expect(typeof claims.exp).toBe('number');
      expect(typeof claims.iat).toBe('number');
      expect(typeof claims.auth_time).toBe('number');
      // Only `openid` was granted: no email and no profile claims.
      for (const absent of ['email', 'email_verified', 'name', 'given_name', 'family_name']) {
        expect(claims).not.toHaveProperty(absent);
      }
    });

    it('carries email claims only with the email scope and profile claims only with profile', async () => {
      const { client_id } = await register({ grant_types: both });
      const email = await codeFor(client_id, 'alice@acme.test', { scope: 'openid email' });
      const withEmail = claimsOf((await json(await redeem(client_id, email.code, email.verifier))).id_token);
      expect(withEmail).toMatchObject({ email: 'alice@acme.test', email_verified: true });
      expect(withEmail).not.toHaveProperty('name');

      const profile = await codeFor(client_id, 'alice@acme.test', { scope: 'openid profile' });
      const withProfile = claimsOf((await json(await redeem(client_id, profile.code, profile.verifier))).id_token);
      expect(withProfile).toMatchObject({ name: 'Alice Smith', given_name: 'Alice', family_name: 'Smith' });
      expect(withProfile).not.toHaveProperty('email');
      expect(withProfile).not.toHaveProperty('nonce');

      // Profile values that do not exist are omitted, not sent empty.
      const bob = await codeFor(client_id, 'bob@other.test', { scope: 'openid profile' });
      const bobClaims = claimsOf((await json(await redeem(client_id, bob.code, bob.verifier))).id_token);
      for (const absent of ['name', 'given_name', 'family_name']) expect(bobClaims).not.toHaveProperty(absent);
    });

    it('is not issued without openid, and not on refresh', async () => {
      const { client_id } = await register({ grant_types: both });
      const plain = await codeFor(client_id, 'alice@acme.test', { scope: 'profile email' });
      expect(await json(await redeem(client_id, plain.code, plain.verifier))).not.toHaveProperty('id_token');

      const oidc = await codeFor(client_id, 'alice@acme.test', { scope: 'openid' });
      const tokens = await json(await redeem(client_id, oidc.code, oidc.verifier));
      expect(tokens.id_token).toBeTruthy();
      expect(await json(await refresh(client_id, tokens.refresh_token))).not.toHaveProperty('id_token');
    });
  });

  it('refuses a code whose membership was revoked between authorize and token', async () => {
    const { client_id } = await register({ grant_types: ['authorization_code', 'refresh_token'] });
    const acme = ws.organizations.findOneBy('name', 'Acme')!;
    const { code, verifier } = await codeFor(client_id, 'alice@acme.test', { organization_id: acme.id });
    const membership = ws.organizationMemberships.findBy(
      'user_id',
      ws.users.findOneBy('email', 'alice@acme.test')!.id,
    )[0];
    ws.organizationMemberships.delete(membership.id);
    const res = await redeem(client_id, code, verifier);
    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('invalid_grant');
  });

  it('refuses a code whose user was deleted between authorize and token, and a refresh for one', async () => {
    const { client_id } = await register({ grant_types: ['authorization_code', 'refresh_token'] });
    const first = await codeFor(client_id, 'bob@other.test');
    ws.users.delete(ws.users.findOneBy('email', 'bob@other.test')!.id);
    expect((await json(await redeem(client_id, first.code, first.verifier))).error).toBe('invalid_grant');

    const second = await codeFor(client_id, 'alice@acme.test');
    const tokens = await json(await redeem(client_id, second.code, second.verifier));
    ws.users.delete(ws.users.findOneBy('email', 'alice@acme.test')!.id);
    const refresh = await server.app.request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id,
        refresh_token: tokens.refresh_token,
      }).toString(),
    });
    expect((await json(refresh)).error).toBe('invalid_grant');
  });
});

describe('AuthKit OAuth server, multi-step interactive sign-in', () => {
  let emulator: Emulator;

  beforeEach(async () => {
    emulator = await createEmulator({
      port: 0,
      interactiveAuth: { password: true },
      seed: {
        resourceIndicators: [{ uri: 'https://mcp.example.test' }],
        users: [
          { email: 'plain@acme.test' },
          { email: 'pw@acme.test', password: 'correct-horse', email_verified: true },
          { email: 'multi@acme.test', password: 'correct-horse', email_verified: true },
          // Every gate at once: unverified mailbox, second factor, two organizations.
          { email: 'gated@acme.test', password: 'correct-horse', totp: true },
        ],
        organizations: [
          { name: 'Alpha', memberships: [{ email: 'multi@acme.test' }, { email: 'gated@acme.test' }] },
          { name: 'Beta', memberships: [{ email: 'multi@acme.test' }, { email: 'gated@acme.test' }] },
        ],
      },
    });
  });

  afterEach(async () => {
    await emulator.close();
  });

  const ews = () => getWorkOSStore(emulator.store);
  const hiddenFields = (html: string) =>
    Object.fromEntries(
      [...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map((m) => [m[1], m[2]]),
    );

  /** Register a public client and start authorize; resolves to the first hosted page and the PKCE verifier. */
  async function begin() {
    const reg = (await (
      await fetch(`${emulator.url}/oauth2/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: [callback],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code', 'refresh_token'],
        }),
      })
    ).json()) as { client_id: string };
    const { verifier, challenge } = pkce();
    const authorize = await fetch(
      `${emulator.url}/oauth2/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: reg.client_id,
        redirect_uri: callback,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        resource: 'https://mcp.example.test',
      })}`,
      { redirect: 'manual' },
    );
    const page = await fetch(authorize.headers.get('location')!, { redirect: 'manual' });
    expect(page.status).toBe(200);
    return { client_id: reg.client_id, verifier, html: await page.text() };
  }

  const submit = (fields: Record<string, string>) =>
    fetch(`${emulator.url}/user_management/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields),
    });

  const exchange = async (client_id: string, verifier: string, callbackUrl: string) => {
    const done = new URL(callbackUrl);
    expect(`${done.origin}${done.pathname}`).toBe(callback);
    const res = await fetch(`${emulator.url}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id,
        code: done.searchParams.get('code')!,
        redirect_uri: callback,
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(200);
    return (await res.json()) as { access_token: string; refresh_token: string };
  };

  it('carries connect_request through the password page to a working exchange', async () => {
    const { client_id, verifier, html } = await begin();
    const carried = hiddenFields(html);
    expect(carried.connect_request).toMatch(/^connect_req_/);

    const passwordPage = await submit({ ...carried, email: 'pw@acme.test' });
    expect(passwordPage.status).toBe(200);
    const passwordHtml = await passwordPage.text();
    expect(passwordHtml).toContain('name="password"');
    expect(hiddenFields(passwordHtml).connect_request).toBe(carried.connect_request);

    const wrong = await submit({ ...hiddenFields(passwordHtml), password: 'nope' });
    expect(wrong.status).toBe(401);
    const ok = await submit({ ...hiddenFields(passwordHtml), password: 'correct-horse' });
    expect(ok.status).toBe(302);
    const tokens = await exchange(client_id, verifier, ok.headers.get('location')!);
    expect(decode(tokens.access_token)).toMatchObject({
      client_id,
      aud: 'https://mcp.example.test',
      sub: ews().users.findOneBy('email', 'pw@acme.test')!.id,
    });
    expect(ews().sessions.all().at(-1)!.auth_method).toBe('password');
  });

  it('carries connect_request through organization selection, and binds the chosen organization', async () => {
    const { client_id, verifier, html } = await begin();
    const passwordHtml = await (await submit({ ...hiddenFields(html), email: 'multi@acme.test' })).text();
    const orgPage = await submit({ ...hiddenFields(passwordHtml), password: 'correct-horse' });
    expect(orgPage.status).toBe(200);
    const orgHtml = await orgPage.text();
    expect(orgHtml).toContain('Select an organization');
    const fields = hiddenFields(orgHtml);
    expect(fields.connect_request).toBeTruthy();
    const orgId = orgHtml.match(/name="organization_id" value="([^"]+)"/)![1];

    const done = await submit({ ...fields, organization_id: orgId });
    expect(done.status).toBe(302);
    const tokens = await exchange(client_id, verifier, done.headers.get('location')!);
    expect(decode(tokens.access_token).org_id).toBe(orgId);
    // The refresh carries the organization across.
    const refreshed = await fetch(`${emulator.url}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id, refresh_token: tokens.refresh_token }),
    });
    expect(decode(((await refreshed.json()) as any).access_token).org_id).toBe(orgId);
  });

  it('carries connect_request through email verification and a second factor, then organization selection', async () => {
    const { client_id, verifier, html } = await begin();
    let page = await (await submit({ ...hiddenFields(html), email: 'gated@acme.test' })).text();
    page = await (await submit({ ...hiddenFields(page), password: 'correct-horse' })).text();
    expect(page).toContain('Verify your email');
    const login = () =>
      emulator.store.getData<{ email_verification_id: string | null; challenge_id: string | null }>(
        `interactive_login:${hiddenFields(page).pending_authentication_token}`,
      )!;
    const emailCode = ews().emailVerifications.get(login().email_verification_id!)!.code;
    page = await (await submit({ ...hiddenFields(page), code: emailCode })).text();
    expect(page).toContain('one-time code');
    const totp = ews().authChallenges.get(login().challenge_id!)!.code!;
    page = await (await submit({ ...hiddenFields(page), code: totp })).text();
    expect(page).toContain('Select an organization');
    const orgId = page.match(/name="organization_id" value="([^"]+)"/)![1];
    expect(hiddenFields(page).connect_request).toBeTruthy();

    const done = await submit({ ...hiddenFields(page), organization_id: orgId });
    expect(done.status).toBe(302);
    const tokens = await exchange(client_id, verifier, done.headers.get('location')!);
    expect(decode(tokens.access_token).org_id).toBe(orgId);
    // The gate that cleared last is what the session and event report, as for the API grants.
    expect(ews().users.findOneBy('email', 'gated@acme.test')!.email_verified).toBe(true);
  });

  it('sends a submit that skips the password page back to it', async () => {
    const first = await begin();
    const skipped = await submit({ ...hiddenFields(first.html), email: 'pw@acme.test' });
    expect(skipped.status).toBe(200);
    expect(await skipped.text()).toContain('name="password"');
  });
});
