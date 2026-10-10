# spacetimedb-oauth for TypeScript (submodule)

OAuth account linking as a **SpacetimeDB submodule**: PKCE, private tokens, scheduled refresh.

Source: [`src/index.ts`](src/index.ts) · Complete example: [`demo/typescript`](../demo/typescript/src/index.ts) ·
Protocol: [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)

## Install

```bash
npm install @pogly/spacetimedb-oauth spacetimedb
```

Use `spacetimedb` 2.11.x, and keep only one copy of it in your module's dependency tree. With two copies,
`spacetime publish` fails with *"Local module schema inspection failed"*. The package ships compiled JavaScript plus
its TypeScript source, which is where the types come from. It depends on `@noble/hashes`.

To work on it from a clone instead, add this folder to your npm workspaces next to your module:

```jsonc
// package.json at your repo root
{ "private": true, "workspaces": ["spacetimedb-oauth/typescript", "my-module"] }
// my-module/package.json
{ "dependencies": { "spacetimedb": "2.11.*", "@pogly/spacetimedb-oauth": "*" } }
```

## Wire it up

Submodules can't read env vars or register routes, so your module hands the config in and adds the callback:

```typescript
import { schema, t, Router } from 'spacetimedb/server';
import * as oauth from '@pogly/spacetimedb-oauth';                 // `import * as`, not a default import

const spacetimedb = schema({ /* your tables */, oauth }, { env: { OAUTH_CONFIG: t.string(), OAUTH_SECRET: t.string() } });
export default spacetimedb;

const configure = (ctx) => oauth.configure(ctx.as.oauth, { config: ctx.env.OAUTH_CONFIG, secret: ctx.env.OAUTH_SECRET });
export const init = spacetimedb.init(configure);
export const oauthKick = spacetimedb.reducer(configure);    // run after `spacetime publish --env-only`

export const oauthCallback = spacetimedb.httpHandler((ctx, req) => oauth.callback(ctx.as.oauth, req));
export const router = spacetimedb.httpRouter(new Router().get('/oauth/callback', oauthCallback));

// Calling a provider API as the caller, from your own procedure:
const { status, body } = oauth.get(ctx.as.oauth, ctx.sender, 'twitch', 'https://api.twitch.tv/helix/users');
```

The library functions are `configure`, `get`, `withToken`, `unlinkAccount`, `linkedAccount` and `parseConfig`. They
match the Rust and C# versions.

## Names

Submodule names are namespaced: the view is `oauth.my_accounts` (client: `conn.db['oauth.my_accounts']`), and the
procedures are `oauth.begin`, `oauth.complete` and `oauth.unlink` (client: `conn.procedures['oauth.begin']`). Rust and
C# use `oauth_my_accounts` / `oauth_begin`. Arguments and results are identical.
[`demo/web/src/api.ts`](../demo/web/src/api.ts) shows one client handling both.
