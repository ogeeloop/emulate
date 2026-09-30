import { generateId, type Store } from '../core/index.js';
import { STORE_KEY_PREFIXES } from './constants.js';
import { expiresIn, isExpired } from './helpers.js';

/** A validated `/oauth2/authorize` request held while the hosted sign-in runs. */
export interface ConnectAuthorizeRequest {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string | null;
  code_challenge_method: string | null;
  scope: string[];
  resource: string | null;
  /** OIDC `nonce`, echoed into the `id_token`. */
  nonce: string | null;
  expires_at: string;
}

const requestKey = (token: string) => `${STORE_KEY_PREFIXES.connectAuthorize}${token}`;

/** Store one validated request and discard abandoned requests that have expired. */
export function createConnectAuthorizeRequest(
  store: Store,
  request: Omit<ConnectAuthorizeRequest, 'expires_at'>,
): string {
  store.deleteDataByPrefix(STORE_KEY_PREFIXES.connectAuthorize, (value) =>
    isExpired((value as ConnectAuthorizeRequest).expires_at),
  );
  const token = generateId('connect_req');
  store.setData(requestKey(token), { ...request, expires_at: expiresIn(10) });
  return token;
}

/** Read a live request, removing an expired one when it is encountered. */
export function getConnectAuthorizeRequest(store: Store, token: string): ConnectAuthorizeRequest | undefined {
  const key = requestKey(token);
  const request = store.getData<ConnectAuthorizeRequest>(key);
  if (request && !isExpired(request.expires_at)) return request;
  if (request) store.deleteData(key);
  return undefined;
}

/** Consume a request after it has produced its single authorization code. */
export function consumeConnectAuthorizeRequest(store: Store, token: string): ConnectAuthorizeRequest | undefined {
  const request = getConnectAuthorizeRequest(store, token);
  if (request) store.deleteData(requestKey(token));
  return request;
}

/** Remove every parked sign-in for a deleted Connect application. */
export function deleteConnectAuthorizeRequestsForClient(store: Store, clientId: string): number {
  return store.deleteDataByPrefix(
    STORE_KEY_PREFIXES.connectAuthorize,
    (value) => (value as ConnectAuthorizeRequest).client_id === clientId,
  );
}
