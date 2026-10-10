# spacetimedb-oauth-client

The browser side of linking, in three functions. It doesn't depend on your generated bindings: you pass your
`oauth_begin` and `oauth_complete` calls in.

```ts
import { linkAccount, linkByRedirect, completeFromRedirect } from '@pogly/spacetimedb-oauth-client';

const unwrap = async (p) => { const r = await p; if ('err' in r) throw new Error(r.err); return r.ok; };
const opts = {
  provider: 'twitch',
  begin: (provider, scopes, returnTo) => unwrap(conn.procedures.oauthBegin({ provider, scopes, returnTo })),
  complete: (state, code) => unwrap(conn.procedures.oauthComplete({ state, code })),
};

// Popup (call from a click): resolves to the linked login
button.onclick = async () => console.log('linked as', await linkAccount(opts));

// Or a full-page redirect, finished on the way back in:
linkButton.onclick = () => linkByRedirect(opts);
const login = await completeFromRedirect(opts.complete);   // null if this load isn't a redirect back
```

`linkAccount` opens the popup synchronously (so blockers allow it), accepts the callback's message only from the
callback's origin and only for its own `state`, and rejects if the user closes the popup. For redirect mode, keep your
SpacetimeDB token across the page load: the identity that finishes must be the one that started.

```bash
npm install @pogly/spacetimedb-oauth-client
```
