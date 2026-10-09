# Demo

Link an account at a **mock OAuth provider** (popup or redirect), see it in the `oauth_my_accounts` view, call the
provider's API through the module with the stored token, and unlink. The same demo exists in all three languages, and
they share one web page ([`web/`](web)), which each module serves from its own HTTP route.

```bash
npm install && npm run build:web                 # bundles web/ into web/dist/index.html
scripts/dev-server.sh build && scripts/dev-server.sh start   # a local server whose modules may call localhost
scripts/e2e.sh rust                              # starts the mock provider, publishes demo/rust, runs the tests
```

Or by hand: `node tests/mock-provider.mjs --port 4110`, then publish with an `OAUTH_CONFIG` pointing at it (copy the one
in [`scripts/e2e.sh`](../scripts/e2e.sh)) and open `http://127.0.0.1:3000/v1/database/oauth-rust/route/`.

Why a special server build? Standalone SpacetimeDB blocks module HTTP to loopback and private addresses (SSRF
protection), and the mock provider runs on localhost. On Maincloud, with real providers, you don't need any of this.

The mock provider ([`tests/mock-provider.mjs`](../tests/mock-provider.mjs)) implements authorization code + PKCE (S256),
rotating refresh tokens, revocation, userinfo and a protected `/api/me`, plus admin endpoints the tests use to expire
and revoke tokens. Client `demo-client` / `demo-secret`; users alice, bob and carol.
