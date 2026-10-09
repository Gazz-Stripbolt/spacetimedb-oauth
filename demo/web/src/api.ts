// One client API over both schema flavours:
//   flat: Rust and C# modules       (view `oauth_my_accounts`, procedures `oauth_begin`, ...)
//   ns:   the TypeScript submodule  (view `oauth.my_accounts`, procedures `oauth.begin`, ...)
// Arguments and results are identical; only the names differ.
import type { Identity } from 'spacetimedb';
import { DbConnection as FlatConnection } from './bindings/index';
import { DbConnection as NsConnection } from './bindings-ns/index';
import type { OauthAccountInfo } from './bindings/types';

export type Flavor = 'flat' | 'ns';
export type Conn = FlatConnection;
export type AccountInfo = OauthAccountInfo;
type Result<T> = { ok: T } | { err: string };

export interface OAuthApi {
  flavor: Flavor;
  conn: Conn;
  identity: Identity;
  token: string;
  /** The caller's linked accounts (a view). */
  accounts: FlatConnection['db']['oauthMyAccounts'];
  /** SQL name of the view, for subscriptions. */
  accountsSql: string;
  begin(provider: string, scopes?: string, returnTo?: string): Promise<string>;
  /** Resolves to the linked login. */
  complete(state: string, code: string): Promise<string>;
  unlink(provider: string): Promise<string>;
  /** The demo's procedure: GET `url` as the caller's `provider` account. */
  profile(provider: string, url: string): Promise<string>;
}

/** Results come back as `{ ok }` / `{ err }`; turn `err` into a rejection. */
async function unwrap<T>(p: Promise<unknown>): Promise<T> {
  const r = (await p) as Result<T>;
  if ('err' in r) throw new Error(r.err);
  return r.ok;
}

export function connect(flavor: Flavor, host: string, db: string, token?: string, onDisconnect?: () => void): Promise<OAuthApi> {
  const Builder = flavor === 'ns' ? NsConnection : FlatConnection;
  return new Promise((resolve, reject) => {
    Builder.builder()
      .withUri(host)
      .withDatabaseName(db)
      .withToken(token)
      .onConnect((c, identity, tok) => resolve(wrap(flavor, c as unknown as Conn, identity, tok)))
      .onDisconnect(() => onDisconnect?.())
      .onConnectError((_c, e) => reject(e))
      .build();
  });
}

function wrap(flavor: Flavor, conn: Conn, identity: Identity, token: string): OAuthApi {
  const ns = flavor === 'ns';
  const d = conn.db as any;
  const p = conn.procedures as any;
  const proc = (flat: string, nsName: string) => p[ns ? nsName : flat];
  return {
    flavor,
    conn,
    identity,
    token,
    accounts: ns ? d['oauth.my_accounts'] : d.oauthMyAccounts,
    accountsSql: ns ? 'oauth.my_accounts' : 'oauth_my_accounts',
    begin: (provider, scopes = '', returnTo = '') => unwrap(proc('oauthBegin', 'oauth.begin')({ provider, scopes, returnTo })),
    complete: (state, code) => unwrap(proc('oauthComplete', 'oauth.complete')({ state, code })),
    unlink: (provider) => unwrap(proc('oauthUnlink', 'oauth.unlink')({ provider })),
    profile: (provider, url) => unwrap(p.demoProfile({ provider, url })),
  };
}
