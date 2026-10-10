/**
 * Demo: link an account at a (mock) OAuth provider, in TypeScript, using `spacetimedb-oauth` as a
 * submodule. Same behaviour as demo/rust and demo/csharp; serves the web client at /route/.
 */
import { schema, t, Router, SyncResponse } from 'spacetimedb/server';
import * as oauth from '@pogly/spacetimedb-oauth';
import PAGE from './page.gen';

const spacetimedb = schema(
  { oauth },
  { env: { OAUTH_CONFIG: t.string(), OAUTH_SECRET: t.string() } }
);
export default spacetimedb;

// ---------------------------------------------------------------------------
// oauth wiring: config in (submodules can't read env) and the callback route
// ---------------------------------------------------------------------------

const configure = (ctx: { env: { OAUTH_CONFIG: string; OAUTH_SECRET: string }; as: { oauth: oauth.OauthCtx } }) =>
  oauth.configure(ctx.as.oauth, { config: ctx.env.OAUTH_CONFIG, secret: ctx.env.OAUTH_SECRET });

export const init = spacetimedb.init((ctx) => configure(ctx));
/** Re-read config after `spacetime publish --env-only`. */
export const oauthKick = spacetimedb.reducer((ctx) => configure(ctx));

export const oauthCallback = spacetimedb.httpHandler((ctx, req) => oauth.callback(ctx.as.oauth, req));

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

/** Call the provider's API as the caller. Shows `oauth.get` refreshing and retrying behind the scenes. */
export const demoProfile = spacetimedb.procedure(
  { provider: t.string(), url: t.string() },
  t.result(t.string(), t.string()),
  (ctx, { provider, url }) => {
    try {
      const r = oauth.get(ctx.as.oauth, ctx.sender, provider, url);
      // `t.result()` values are `{ ok }` / `{ err }` at runtime; 2.11 types them as `Ok | Err`.
      return (r.status >= 400 ? { err: `${r.status}: ${r.body}` } : { ok: r.body }) as unknown as string;
    } catch (e) {
      return { err: String((e as Error).message) } as unknown as string;
    }
  }
);

// The shared web client, told that this module uses the submodule's namespaced names.
const NS_PAGE = PAGE.replace('data-flavor="flat"', 'data-flavor="ns"');
export const page = spacetimedb.httpHandler(
  () => new SyncResponse(NS_PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } })
);
export const router = spacetimedb.httpRouter(new Router().get('/', page).get('/oauth/callback', oauthCallback));
