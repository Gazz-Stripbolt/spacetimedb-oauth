/**
 * # spacetimedb-oauth: link OAuth accounts to SpacetimeDB identities, as a submodule
 *
 * The TypeScript twin of `rust/oauth.rs` and `csharp/OAuth.cs`: the authorization code flow with
 * PKCE, tokens in private tables, a `my_accounts` view, scheduled refresh, and `withToken` /
 * `get` helpers that refresh on demand and retry once on a 401.
 *
 * Mount it with `schema({ ..., oauth })`. Submodules can't read env vars or register routes, so
 * the consumer passes config in with `configure()` and registers the callback handler; see
 * `README.md`.
 */
import { schema, table, t, SyncResponse } from 'spacetimedb/server';
import type { ReducerCtx, ProcedureCtx, HandlerContext, Request } from 'spacetimedb/server';
import { ScheduleAt, TimeDuration, Timestamp, type Identity } from 'spacetimedb';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';

// ---------------------------------------------------------------------------
// Tables (they live under the consumer's namespace, e.g. `oauth.account`)
// ---------------------------------------------------------------------------

/** The consumer's OAUTH_CONFIG and OAUTH_SECRET, handed in through `configure()`. */
const config = table({ name: 'config' }, { key: t.u8().primaryKey(), config: t.string(), secret: t.string() });

/** A link attempt in progress: single-use, short-lived, bound to the identity that started it. */
const state = table(
  { name: 'state' },
  {
    state: t.string().primaryKey(),
    identity: t.identity().index('btree'),
    provider: t.string(),
    verifier: t.string(),
    scopes: t.string(),
    returnTo: t.string(),
    createdAt: t.timestamp(),
    expiresAt: t.timestamp(),
  }
);

/** A linked account. Private: clients read their own through `my_accounts`. */
const account = table(
  { name: 'account', indexes: [{ accessor: 'byExternal', algorithm: 'btree', columns: ['provider', 'externalId'] }] },
  {
    id: t.u64().primaryKey().autoInc(),
    identity: t.identity().index('btree'),
    provider: t.string(),
    externalId: t.string(),
    login: t.string(),
    scopes: t.string(),
    linkedAt: t.timestamp(),
    /** `ok`, or `relink` when the provider stopped accepting the refresh token. */
    status: t.string(),
    lastError: t.string(),
  }
);

/** The secrets. Private, never exposed by any view. */
const token = table(
  { name: 'token' },
  {
    accountId: t.u64().primaryKey(),
    accessToken: t.string(),
    refreshToken: t.option(t.string()),
    expiresAt: t.option(t.timestamp()),
    refreshedAt: t.timestamp(),
    refreshingUntil: t.option(t.timestamp()),
    refreshFailures: t.u32(),
  }
);

const refreshJob = table(
  { name: 'refresh_job' },
  { scheduledId: t.u64().primaryKey().autoInc(), scheduledAt: t.scheduleAt(), accountId: t.u64().index('btree') }
);

/** What a client may know about its own linked accounts. */
export const AccountInfo = t.object('OauthAccountInfo', {
  provider: t.string(),
  externalId: t.string(),
  login: t.string(),
  scopes: t.string(),
  linkedAt: t.timestamp(),
  status: t.string(),
  expiresAt: t.option(t.timestamp()),
});

const spacetimedb = schema({ config, state, account, token, refreshJob });
export default spacetimedb;

type S = typeof spacetimedb.schemaType;
/** Contexts narrowed to this submodule: pass `ctx.as.oauth` (or whatever you named it). */
export type OauthCtx = ReducerCtx<S>;
export type OauthProcedureCtx = ProcedureCtx<S>;
export type OauthHandlerCtx = HandlerContext<S>;
type Tx = OauthCtx;
type Account = NonNullable<ReturnType<Tx['db']['account']['id']['find']>>;
type Token = NonNullable<ReturnType<Tx['db']['token']['accountId']['find']>>;
export type AccountInfo = {
  provider: string;
  externalId: string;
  login: string;
  scopes: string;
  linkedAt: Timestamp;
  status: string;
  expiresAt: Timestamp | undefined;
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Store the config. Call it from your `init`, and from a reducer you run after
 * `spacetime publish --env-only` (submodules can't read env vars themselves).
 * `config` is the OAUTH_CONFIG JSON string, `secret` a long random string.
 */
export function configure(ctx: OauthCtx, cfg: { config: string; secret: string }): void {
  parseConfig(cfg.config); // fail early on a bad config
  const row = { key: 0, config: cfg.config, secret: cfg.secret };
  if (ctx.db.config.key.find(0)) ctx.db.config.key.update(row);
  else ctx.db.config.insert(row);
}

export interface Provider {
  name: string;
  clientId: string;
  clientSecret: string;
  authorizeUrl: string;
  tokenUrl: string;
  revokeUrl: string;
  userinfoUrl: string;
  idPath: string;
  loginPath: string;
  scopes: string;
  tokenAuth: 'post' | 'basic';
  authorizeParams: [string, string][];
  apiHeaders: [string, string][];
  eagerRefresh: boolean;
}

export interface Config {
  baseUrl: string;
  appUrls: string[];
  stateTtlSecs: number;
  refreshMarginSecs: number;
  providers: Provider[];
}

/** Built-in provider settings. Anything can be overridden in the config. */
function preset(name: string): Record<string, unknown> {
  switch (name) {
    case 'twitch':
      return {
        authorize_url: 'https://id.twitch.tv/oauth2/authorize', token_url: 'https://id.twitch.tv/oauth2/token',
        revoke_url: 'https://id.twitch.tv/oauth2/revoke', userinfo_url: 'https://api.twitch.tv/helix/users',
        id_path: 'data.0.id', login_path: 'data.0.login', api_headers: { 'Client-Id': '{client_id}' },
      };
    case 'discord':
      return {
        authorize_url: 'https://discord.com/oauth2/authorize', token_url: 'https://discord.com/api/oauth2/token',
        revoke_url: 'https://discord.com/api/oauth2/token/revoke', userinfo_url: 'https://discord.com/api/users/@me',
        id_path: 'id', login_path: 'username', scopes: 'identify',
      };
    case 'google':
      return {
        authorize_url: 'https://accounts.google.com/o/oauth2/v2/auth', token_url: 'https://oauth2.googleapis.com/token',
        revoke_url: 'https://oauth2.googleapis.com/revoke', userinfo_url: 'https://openidconnect.googleapis.com/v1/userinfo',
        id_path: 'sub', login_path: 'email', scopes: 'openid email profile',
        authorize_params: { access_type: 'offline', prompt: 'consent' },
      };
    case 'github':
      return {
        authorize_url: 'https://github.com/login/oauth/authorize', token_url: 'https://github.com/login/oauth/access_token',
        userinfo_url: 'https://api.github.com/user', id_path: 'id', login_path: 'login', scopes: 'read:user',
      };
    case 'spotify':
      return {
        authorize_url: 'https://accounts.spotify.com/authorize', token_url: 'https://accounts.spotify.com/api/token',
        userinfo_url: 'https://api.spotify.com/v1/me', id_path: 'id', login_path: 'display_name',
        scopes: 'user-read-private', token_auth: 'basic',
      };
    default:
      return { id_path: 'sub', login_path: 'preferred_username' };
  }
}

export function parseConfig(raw: string): Config {
  let v: any;
  try {
    v = JSON.parse(raw);
  } catch (e) {
    throw new Error(`OAUTH_CONFIG is not JSON: ${(e as Error).message}`);
  }
  if (typeof v?.base_url !== 'string') throw new Error('OAUTH_CONFIG.base_url is required');
  const baseUrl = v.base_url.replace(/\/+$/, '');
  const appUrls = [`${baseUrl}/route/`, ...(Array.isArray(v.app_urls) ? v.app_urls.filter((u: unknown) => typeof u === 'string') : [])];
  if (!v.providers || typeof v.providers !== 'object') throw new Error('OAUTH_CONFIG.providers is required');
  const providers: Provider[] = [];
  for (const [name, over] of Object.entries<any>(v.providers)) {
    const m: any = { ...preset(over?.preset ?? name), ...over };
    const s = (k: string) => (typeof m[k] === 'string' ? m[k] : '');
    const pairs = (k: string): [string, string][] => Object.entries(m[k] ?? {}).map(([a, b]) => [a, String(b)]);
    const p: Provider = {
      name,
      clientId: s('client_id'),
      clientSecret: s('client_secret'),
      authorizeUrl: s('authorize_url'),
      tokenUrl: s('token_url'),
      revokeUrl: s('revoke_url'),
      userinfoUrl: s('userinfo_url'),
      idPath: s('id_path'),
      loginPath: s('login_path'),
      scopes: s('scopes'),
      tokenAuth: s('token_auth') === 'basic' ? 'basic' : 'post',
      authorizeParams: pairs('authorize_params'),
      apiHeaders: pairs('api_headers'),
      eagerRefresh: m.eager_refresh !== false,
    };
    for (const [field, val] of [['client_id', p.clientId], ['authorize_url', p.authorizeUrl], ['token_url', p.tokenUrl], ['userinfo_url', p.userinfoUrl]]) {
      if (!val) throw new Error(`provider \`${name}\` is missing \`${field}\``);
    }
    providers.push(p);
  }
  return {
    baseUrl,
    appUrls,
    stateTtlSecs: typeof v.state_ttl_secs === 'number' ? v.state_ttl_secs : 600,
    refreshMarginSecs: typeof v.refresh_margin_secs === 'number' ? v.refresh_margin_secs : 300,
    providers,
  };
}

const providerOf = (cfg: Config, name: string): Provider => {
  const p = cfg.providers.find((x) => x.name === name);
  if (!p) throw new Error(`unknown provider \`${name}\``);
  return p;
};
const redirectUri = (cfg: Config) => `${cfg.baseUrl}/route/oauth/callback`;
const allowed = (cfg: Config, url: string) => cfg.appUrls.some((p) => url.startsWith(p));

function loadConfig(tx: Tx): { cfg: Config; secret: string } {
  const row = tx.db.config.key.find(0);
  if (!row) throw new Error('oauth is not configured: call oauth.configure() from your init');
  return { cfg: parseConfig(row.config), secret: row.secret };
}

const HTTP_TIMEOUT = TimeDuration.fromMillis(10_000);
const LEASE_US = 30n * 1_000_000n;
const MAX_PENDING = 5;
const MAX_REFRESH_FAILURES = 8;

// ---------------------------------------------------------------------------
// The view and client procedures (registered under the namespace: `oauth.begin`, ...)
// ---------------------------------------------------------------------------

const info = (a: Account, tk: Token | undefined): AccountInfo => ({
  provider: a.provider,
  externalId: a.externalId,
  login: a.login,
  scopes: a.scopes,
  linkedAt: a.linkedAt,
  status: a.status,
  expiresAt: tk?.expiresAt,
});

/** The caller's linked accounts. Never includes tokens. */
export const myAccounts = spacetimedb.view({ name: 'my_accounts', public: true }, t.array(AccountInfo), (ctx) =>
  [...ctx.db.account.identity.filter(ctx.sender)].map((a) => info(a, ctx.db.token.accountId.find(a.id) ?? undefined))
);

type Res<T> = { ok: T } | { err: string };
/**
 * Run `f` and return its result as a SpacetimeDB `Result`. The runtime serializes `{ ok }` /
 * `{ err }`, but 2.11's `t.result()` types its value as `Ok | Err`, hence the cast.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const attempt = <T>(f: () => T): any => {
  try {
    return { ok: f() } satisfies Res<T>;
  } catch (e) {
    return { err: String((e as Error)?.message ?? e) } satisfies Res<T>;
  }
};

/**
 * Start linking: returns the provider's authorize URL. `scopes` '' = the provider's defaults.
 * `returnTo` '' = popup mode; otherwise the browser is redirected there with
 * `#oauth_state=..&oauth_code=..`.
 */
export const begin = spacetimedb.procedure(
  { provider: t.string(), scopes: t.string(), returnTo: t.string() },
  t.result(t.string(), t.string()),
  (ctx, { provider, scopes, returnTo }) =>
    attempt(() => {
      const { cfg, secret } = ctx.withTx((tx) => loadConfig(tx));
      const p = providerOf(cfg, provider);
      const sc = scopes.trim() || p.scopes;
      if (/[\u0000-\u001f"]/.test(sc)) throw new Error('bad scopes');
      if (returnTo && !allowed(cfg, returnTo)) throw new Error('return_to is not an allowed app URL');
      const who = ctx.sender;
      const seed = `${who.toHexString()}|${ctx.timestamp.microsSinceUnixEpoch}|${ctx.newUuidV7().toString()}`;
      const st = b64url(mac(secret, `state|${seed}`));
      const verifier = b64url(mac(secret, `verifier|${seed}`));
      const challenge = b64url(sha256(enc.encode(verifier)));
      const ttl = BigInt(Math.round(cfg.stateTtlSecs * 1e6));
      ctx.withTx((tx) => {
        // Housekeeping: expired attempts, and all but the newest few for this identity.
        for (const s of [...tx.db.state.iter()]) {
          if (s.expiresAt.microsSinceUnixEpoch < tx.timestamp.microsSinceUnixEpoch) tx.db.state.state.delete(s.state);
        }
        const mine = [...tx.db.state.identity.filter(who)].sort((a, b) =>
          a.createdAt.microsSinceUnixEpoch < b.createdAt.microsSinceUnixEpoch ? -1 : 1
        );
        for (const s of mine.slice(0, Math.max(0, mine.length + 1 - MAX_PENDING))) tx.db.state.state.delete(s.state);
        tx.db.state.insert({
          state: st,
          identity: who,
          provider,
          verifier,
          scopes: sc,
          returnTo,
          createdAt: tx.timestamp,
          expiresAt: new Timestamp(tx.timestamp.microsSinceUnixEpoch + ttl),
        });
      });
      const q: [string, string][] = [
        ['response_type', 'code'],
        ['client_id', p.clientId],
        ['redirect_uri', redirectUri(cfg)],
        ['state', st],
        ['code_challenge', challenge],
        ['code_challenge_method', 'S256'],
      ];
      if (sc) q.push(['scope', sc]);
      let url = `${p.authorizeUrl}${p.authorizeUrl.includes('?') ? '&' : '?'}${form(q)}`;
      for (const [k, v] of p.authorizeParams) url += `&${pct(k)}=${pct(v)}`;
      return url;
    })
);

/**
 * Finish linking with the `state` and `code` from the callback. Only the identity that began can
 * finish. Returns the linked login; `my_accounts` has the details.
 *
 * Every procedure here returns `t.result(t.string(), t.string())`: in 2.11 the TS serializer
 * writes `err` with the `ok` side's type, so a Result whose sides differ can't return an error.
 */
export const complete = spacetimedb.procedure(
  { state: t.string(), code: t.string() },
  t.result(t.string(), t.string()),
  (ctx, { state: st, code }) => attempt(() => completeLink(ctx, st, code).login)
);

/** Unlink the caller's account for `provider`, revoking its tokens (best effort). Returns the provider's name. */
export const unlink = spacetimedb.procedure({ provider: t.string() }, t.result(t.string(), t.string()), (ctx, { provider }) =>
  attempt(() => {
    unlinkAccount(ctx, ctx.sender, provider);
    return provider;
  })
);

/** Scheduled: refresh a token ahead of its expiry. */
export const refreshDue = spacetimedb.procedure({ onSchedule: refreshJob }, { arg: refreshJob.rowType }, t.unit(), (ctx, { arg }) => {
  try {
    refresh(ctx, arg.accountId);
  } catch (e) {
    console.info(`oauth: scheduled refresh of account ${arg.accountId}: ${(e as Error).message}`);
  }
  return {};
});

function completeLink(ctx: OauthProcedureCtx, st: string, code: string): AccountInfo {
  const who = ctx.sender;
  const { cfg, pending, error } = ctx.withTx((tx) => {
    const { cfg } = loadConfig(tx);
    const s = tx.db.state.state.find(st);
    if (!s) return { cfg, pending: undefined, error: 'unknown or already used state' };
    if (!s.identity.isEqual(who)) return { cfg, pending: undefined, error: 'this link attempt belongs to another identity' };
    tx.db.state.state.delete(st);
    if (s.expiresAt.microsSinceUnixEpoch < tx.timestamp.microsSinceUnixEpoch) return { cfg, pending: undefined, error: 'link attempt expired, start again' };
    return { cfg, pending: s, error: '' };
  });
  if (!pending) throw new Error(error);
  const p = providerOf(cfg, pending.provider);
  const r = tokenRequest(ctx, p, [
    ['grant_type', 'authorization_code'],
    ['code', code],
    ['redirect_uri', redirectUri(cfg)],
    ['code_verifier', pending.verifier],
  ]);
  if ('error' in r) throw new Error(r.error.message);
  const tokens = r.tokens;
  const access = String(tokens.access_token);
  let ext: { id: string; login: string };
  try {
    ext = userinfo(ctx, p, access);
  } catch (e) {
    revoke(ctx, p, access);
    throw e;
  }
  const scopes = scopesOf(tokens) ?? pending.scopes;
  const refreshToken = typeof tokens.refresh_token === 'string' ? tokens.refresh_token : undefined;
  const linked = ctx.withTx((tx): Res<AccountInfo> => {
    if ([...tx.db.account.byExternal.filter([p.name, ext.id])].some((a) => !a.identity.isEqual(who))) {
      return { err: `that ${p.name} account is already linked to another identity` };
    }
    // One account per provider per identity: re-linking replaces the old one.
    const old = findAccount(tx, who, p.name);
    if (old) deleteAccount(tx, old.id);
    const a = tx.db.account.insert({
      id: 0n,
      identity: who,
      provider: p.name,
      externalId: ext.id,
      login: ext.login,
      scopes,
      linkedAt: tx.timestamp,
      status: 'ok',
      lastError: '',
    });
    const tk = tx.db.token.insert({
      accountId: a.id,
      accessToken: access,
      refreshToken,
      expiresAt: expiresAtOf(tokens, tx.timestamp),
      refreshedAt: tx.timestamp,
      refreshingUntil: undefined,
      refreshFailures: 0,
    });
    if (p.eagerRefresh) scheduleRefresh(tx, tk, cfg.refreshMarginSecs);
    return { ok: info(a, tk) };
  });
  if ('ok' in linked) return linked.ok;
  revoke(ctx, p, access);
  throw new Error(linked.err);
}

// ---------------------------------------------------------------------------
// Library API: call these from your own procedures with `ctx.as.oauth`
// ---------------------------------------------------------------------------

export interface FetchResponse {
  status: number;
  text(): string;
}

/**
 * Run `call` with a valid access token for `who`'s `provider` account. Refreshes first if the
 * token is about to expire, and once more (then retries) if `call` gets a 401.
 */
export function withToken<R extends FetchResponse>(
  ctx: OauthProcedureCtx,
  who: Identity,
  provider: string,
  call: (token: string) => R
): R {
  const cur = ctx.withTx((tx) => {
    const a = findAccount(tx, who, provider);
    if (!a) return { error: `no linked ${provider} account` };
    if (a.status !== 'ok') return { error: `the ${provider} account needs to be linked again` };
    const tk = tx.db.token.accountId.find(a.id);
    if (!tk) return { error: 'no token' };
    return { accountId: a.id, access: tk.accessToken, expiresAt: tk.expiresAt, canRefresh: tk.refreshToken !== undefined };
  });
  if ('error' in cur) throw new Error(cur.error);
  let access = cur.access;
  const soon = ctx.timestamp.microsSinceUnixEpoch + 30n * 1_000_000n;
  if (cur.canRefresh && cur.expiresAt && cur.expiresAt.microsSinceUnixEpoch < soon) access = refresh(ctx, cur.accountId);
  const res = call(access);
  if (res.status !== 401 || !cur.canRefresh) return res;
  return call(refresh(ctx, cur.accountId));
}

/** GET `url` as `who`'s `provider` account (bearer token plus the provider's API headers). */
export function get(ctx: OauthProcedureCtx, who: Identity, provider: string, url: string): { status: number; body: string } {
  const p = providerOf(ctx.withTx((tx) => loadConfig(tx)).cfg, provider);
  const res = withToken(ctx, who, provider, (tk) => ctx.http.fetch(url, { method: 'GET', headers: apiHeaders(p, tk), timeout: HTTP_TIMEOUT }));
  return { status: res.status, body: res.text() };
}

/** Unlink `who`'s `provider` account and revoke its tokens (best effort). */
export function unlinkAccount(ctx: OauthProcedureCtx, who: Identity, provider: string): void {
  const r = ctx.withTx((tx) => {
    const { cfg } = loadConfig(tx);
    const a = findAccount(tx, who, provider);
    if (!a) return { error: `no linked ${provider} account` };
    const tk = tx.db.token.accountId.find(a.id) ?? undefined;
    deleteAccount(tx, a.id);
    return { cfg, tk };
  });
  if ('error' in r) throw new Error(r.error);
  const p = r.cfg.providers.find((x) => x.name === provider);
  if (r.tk && p) revoke(ctx, p, r.tk.refreshToken ?? r.tk.accessToken);
}

/** `who`'s linked account at `provider`, if any. Works in reducers too. */
export function linkedAccount(tx: OauthCtx, who: Identity, provider: string): Account | undefined {
  return findAccount(tx, who, provider);
}

/**
 * The callback route. Register it in your module:
 * `export const oauthCallback = spacetimedb.httpHandler((ctx, req) => oauth.callback(ctx.as.oauth, req));`
 * and route `GET /oauth/callback` to it.
 *
 * No tokens are handled here: the page hands `state` and `code` to the app (popup opener, or
 * `returnTo`), which calls `oauth.complete`.
 */
export function callback(ctx: OauthHandlerCtx, req: Request): SyncResponse {
  const qi = req.url.indexOf('?');
  const q = parseQuery(qi < 0 ? '' : req.url.slice(qi + 1));
  const st = q.get('state') ?? '';
  const code = q.get('code') ?? '';
  const error = q.get('error') ?? '';
  let cfg: Config;
  try {
    cfg = ctx.withTx((tx) => loadConfig(tx)).cfg;
  } catch (e) {
    return html(500, resultPage({ error: (e as Error).message }, []));
  }
  const pending = ctx.withTx((tx) => {
    const s = tx.db.state.state.find(st) ?? undefined;
    // A provider-side error (e.g. the user clicked Deny) ends this attempt.
    if (s && error) tx.db.state.state.delete(st);
    return s;
  });
  const msg: Record<string, string> = { type: 'spacetimedb-oauth', state: st };
  if (pending) msg.provider = pending.provider;
  if (error) {
    const desc = q.get('error_description');
    msg.error = desc ? `${error}: ${desc}` : error;
  } else if (!pending) msg.error = 'unknown or expired link attempt';
  else msg.code = code;
  // Redirect mode: hand the result to the app in the URL fragment (never sent to servers).
  if (pending?.returnTo) {
    const names: Record<string, string> = { state: 'oauth_state', code: 'oauth_code', error: 'oauth_error', provider: 'oauth_provider' };
    const frag = Object.entries(msg)
      .filter(([k]) => k !== 'type')
      .map(([k, v]) => [names[k], v] as [string, string]);
    return new SyncResponse('', { status: 302, headers: { location: `${pending.returnTo}#${form(frag)}`, 'cache-control': 'no-store' } });
  }
  return html(200, resultPage(msg, cfg.appUrls));
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

/** Refresh `accountId`'s token now. Returns the new access token. */
function refresh(ctx: OauthProcedureCtx, accountId: bigint): string {
  const claim = ctx.withTx((tx) => {
    const { cfg } = loadConfig(tx);
    const a = tx.db.account.id.find(accountId);
    if (!a) return { error: 'account is gone' };
    const tk = tx.db.token.accountId.find(accountId);
    if (!tk) return { error: 'token is gone' };
    if (tk.refreshToken === undefined) return { error: 'no refresh token' };
    if (tk.refreshingUntil && tk.refreshingUntil.microsSinceUnixEpoch > tx.timestamp.microsSinceUnixEpoch) {
      return { error: 'a refresh is already in progress, try again shortly' };
    }
    tx.db.token.accountId.update({ ...tk, refreshingUntil: new Timestamp(tx.timestamp.microsSinceUnixEpoch + LEASE_US) });
    return { cfg, provider: a.provider, refreshToken: tk.refreshToken };
  });
  if ('error' in claim) throw new Error(claim.error);
  const p = providerOf(claim.cfg, claim.provider);
  const r = tokenRequest(ctx, p, [
    ['grant_type', 'refresh_token'],
    ['refresh_token', claim.refreshToken],
  ]);
  const out = ctx.withTx((tx): Res<string> => {
    const a = tx.db.account.id.find(accountId);
    const tk = tx.db.token.accountId.find(accountId);
    if (!a || !tk) return { err: 'account is gone' };
    clearJobs(tx, accountId);
    if ('tokens' in r) {
      const at = r.tokens.access_token;
      if (typeof at !== 'string') return { err: 'no access_token in refresh response' };
      const scopes = scopesOf(r.tokens);
      if (scopes !== undefined) tx.db.account.id.update({ ...a, scopes });
      const updated = tx.db.token.accountId.update({
        ...tk,
        accessToken: at,
        refreshToken: typeof r.tokens.refresh_token === 'string' ? r.tokens.refresh_token : tk.refreshToken,
        expiresAt: expiresAtOf(r.tokens, tx.timestamp),
        refreshedAt: tx.timestamp,
        refreshingUntil: undefined,
        refreshFailures: 0,
      });
      if (p.eagerRefresh) scheduleRefresh(tx, updated, claim.cfg.refreshMarginSecs);
      return { ok: at };
    }
    if (r.error.permanent) {
      // The grant is gone (revoked, expired): the user has to link again.
      tx.db.token.accountId.delete(accountId);
      tx.db.account.id.update({ ...a, status: 'relink', lastError: r.error.message });
      return { err: r.error.message };
    }
    const failures = tk.refreshFailures + 1;
    tx.db.account.id.update({ ...a, lastError: r.error.message });
    tx.db.token.accountId.update({ ...tk, refreshingUntil: undefined, refreshFailures: failures });
    if (failures <= MAX_REFRESH_FAILURES) {
      const backoffUs = BigInt(15 * 2 ** Math.min(failures, 8)) * 1_000_000n;
      tx.db.refreshJob.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.time(tx.timestamp.microsSinceUnixEpoch + backoffUs), accountId });
    }
    return { err: r.error.message };
  });
  if ('err' in out) throw new Error(out.err);
  return out.ok;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type TokenResult = { tokens: Record<string, unknown> } | { error: { message: string; permanent: boolean } };

function tokenRequest(ctx: OauthProcedureCtx, p: Provider, params: [string, string][]): TokenResult {
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  const body = [...params];
  if (p.tokenAuth === 'basic') headers.authorization = `Basic ${b64(enc.encode(`${pct(p.clientId)}:${pct(p.clientSecret)}`))}`;
  else body.push(['client_id', p.clientId], ['client_secret', p.clientSecret]);
  let status: number;
  let text: string;
  try {
    const res = ctx.http.fetch(p.tokenUrl, { method: 'POST', headers, body: form(body), timeout: HTTP_TIMEOUT });
    status = res.status;
    text = res.text();
  } catch (e) {
    return { error: { message: `token endpoint: ${(e as Error).message}`, permanent: false } };
  }
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {}
  if (status >= 200 && status < 300 && typeof json?.access_token === 'string') return { tokens: json };
  const code = typeof json?.error === 'string' ? json.error : '';
  const desc = typeof json?.error_description === 'string' ? json.error_description : '';
  return {
    error: {
      message: code ? `${code}: ${desc}` : `token endpoint: ${status} ${text.slice(0, 200)}`,
      permanent: code === 'invalid_grant' || (status >= 400 && status < 500 && status !== 408 && status !== 429),
    },
  };
}

function apiHeaders(p: Provider, tk: string): Record<string, string> {
  const h: Record<string, string> = { authorization: `Bearer ${tk}`, accept: 'application/json', 'user-agent': 'spacetimedb-oauth' };
  for (const [k, v] of p.apiHeaders) h[k] = v.replaceAll('{client_id}', p.clientId);
  return h;
}

function userinfo(ctx: OauthProcedureCtx, p: Provider, tk: string): { id: string; login: string } {
  let res;
  try {
    res = ctx.http.fetch(p.userinfoUrl, { method: 'GET', headers: apiHeaders(p, tk), timeout: HTTP_TIMEOUT });
  } catch (e) {
    throw new Error(`userinfo: ${(e as Error).message}`);
  }
  const text = res.text();
  if (res.status < 200 || res.status >= 300) throw new Error(`userinfo: ${res.status} ${text.slice(0, 200)}`);
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (e) {
    throw new Error(`userinfo is not JSON: ${(e as Error).message}`);
  }
  const id = atPath(v, p.idPath);
  if (id === undefined) throw new Error(`userinfo has no \`${p.idPath}\``);
  return { id, login: atPath(v, p.loginPath) ?? '' };
}

/** Revoke a token at the provider, if it supports revocation. Best effort. */
function revoke(ctx: OauthProcedureCtx, p: Provider, tk: string): void {
  if (!p.revokeUrl) return;
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  const body: [string, string][] = [['token', tk]];
  if (p.tokenAuth === 'basic') headers.authorization = `Basic ${b64(enc.encode(`${pct(p.clientId)}:${pct(p.clientSecret)}`))}`;
  else body.push(['client_id', p.clientId], ['client_secret', p.clientSecret]);
  try {
    ctx.http.fetch(p.revokeUrl, { method: 'POST', headers, body: form(body), timeout: HTTP_TIMEOUT });
  } catch (e) {
    console.info(`oauth: revoke at ${p.name}: ${(e as Error).message}`);
  }
}

function findAccount(tx: Tx, who: Identity, provider: string): Account | undefined {
  return [...tx.db.account.identity.filter(who)].find((a) => a.provider === provider);
}

function deleteAccount(tx: Tx, accountId: bigint): void {
  clearJobs(tx, accountId);
  tx.db.token.accountId.delete(accountId);
  tx.db.account.id.delete(accountId);
}

function clearJobs(tx: Tx, accountId: bigint): void {
  for (const j of [...tx.db.refreshJob.accountId.filter(accountId)]) tx.db.refreshJob.scheduledId.delete(j.scheduledId);
}

/** Refresh `margin` before expiry (at most a fifth of the token's lifetime early). */
function scheduleRefresh(tx: Tx, tk: Token, marginSecs: number): void {
  if (!tk.expiresAt || tk.refreshToken === undefined) return;
  const now = tx.timestamp.microsSinceUnixEpoch;
  const exp = tk.expiresAt.microsSinceUnixEpoch;
  const life = exp - now;
  let early = BigInt(Math.round(marginSecs * 1e6));
  if (life / 5n < early) early = life / 5n;
  if (early < 0n) early = 0n;
  const at = exp - early > now ? exp - early : now;
  tx.db.refreshJob.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.time(at), accountId: tk.accountId });
}

function expiresAtOf(tokens: Record<string, unknown>, now: Timestamp): Timestamp | undefined {
  const secs = Number(tokens.expires_in);
  return Number.isFinite(secs) && secs > 0 ? new Timestamp(now.microsSinceUnixEpoch + BigInt(Math.round(secs * 1e6))) : undefined;
}

/** Granted scopes, space-separated (Twitch returns an array). */
function scopesOf(tokens: Record<string, unknown>): string | undefined {
  const s = tokens.scope;
  if (typeof s === 'string') return s.replaceAll(',', ' ');
  if (Array.isArray(s)) return s.filter((x) => typeof x === 'string').join(' ');
  return undefined;
}

/** `data.0.id` style lookup; numbers come back as strings. */
function atPath(v: unknown, path: string): string | undefined {
  let cur: any = v;
  for (const part of path.split('.').filter(Boolean)) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = Array.isArray(cur) && /^\d+$/.test(part) ? cur[Number(part)] : cur[part];
  }
  return typeof cur === 'string' ? cur : typeof cur === 'number' ? String(cur) : undefined;
}

const enc = new TextEncoder();
const mac = (secret: string, msg: string) => hmac(sha256, enc.encode(secret), enc.encode(msg));

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    for (let j = 0; j < 4; j++) out += j <= bytes.length - i ? B64[(n >> (18 - 6 * j)) & 63] : '=';
  }
  return out;
}
const b64url = (bytes: Uint8Array) => b64(bytes).replace(/=+$/, '').replaceAll('+', '-').replaceAll('/', '_');

/** Percent-encode everything but RFC 3986 unreserved characters. */
const pct = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const form = (pairs: [string, string][]) => pairs.map(([k, v]) => `${pct(k)}=${pct(v)}`).join('&');

/** Query string to a map (URLSearchParams isn't available in modules). */
function parseQuery(q: string): Map<string, string> {
  const dec = (s: string) => {
    try {
      return decodeURIComponent(s.replaceAll('+', ' '));
    } catch {
      return s;
    }
  };
  const m = new Map<string, string>();
  for (const part of q.split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const k = dec(i < 0 ? part : part.slice(0, i));
    if (!m.has(k)) m.set(k, i < 0 ? '' : dec(part.slice(i + 1)));
  }
  return m;
}

const html = (status: number, body: string) =>
  new SyncResponse(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });

/**
 * The page the provider redirects to. It hands the result to the window that opened it, but
 * only if that window is an allowed app URL (same-origin openers are checked by full URL
 * prefix, so another app on a shared host can't receive it).
 */
function resultPage(msg: Record<string, string>, allowedUrls: string[]): string {
  return RESULT_PAGE.replace('/*MSG*/null', JSON.stringify(msg).replaceAll('<', '\\u003c')).replace(
    '/*ALLOWED*/[]',
    JSON.stringify(allowedUrls).replaceAll('<', '\\u003c')
  );
}

const RESULT_PAGE = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linking account</title>
<style>body{margin:0;font:15px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;background:#f6f5f2;color:#1d1c1a}@media(prefers-color-scheme:dark){body{background:#121316;color:#ecebe8}}main{text-align:center;padding:24px}h1{font-size:19px;margin:0 0 6px}p{margin:0;opacity:.7}</style></head>
<body><main><h1 id="t">Linking…</h1><p id="d"></p></main><script>
const msg = /*MSG*/null, allowed = /*ALLOWED*/[];
const t = document.getElementById('t'), d = document.getElementById('d');
let sent = false;
try {
  const o = window.opener;
  if (o) {
    let href = null;
    try { href = o.location.href; } catch (e) {}
    if (href !== null) {
      if (allowed.some((a) => href.startsWith(a))) { o.postMessage(msg, location.origin); sent = true; }
    } else {
      for (const a of allowed) { const u = new URL(a); if (u.origin !== location.origin) { o.postMessage(msg, u.origin); sent = true; } }
    }
  }
} catch (e) {}
if (msg && msg.error) { t.textContent = "Couldn't link the account"; d.textContent = msg.error; }
else if (sent) { t.textContent = 'Almost done'; d.textContent = 'Finishing in the app. You can close this window.'; setTimeout(() => window.close(), 400); }
else { t.textContent = 'Return to the app'; d.textContent = 'Open the app that started linking and try again.'; }
</script></body></html>`;
