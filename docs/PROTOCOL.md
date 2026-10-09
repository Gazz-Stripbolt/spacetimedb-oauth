# Protocol

Everything a client needs to link accounts through a spacetimedb-oauth module. All three server implementations
([`oauth.rs`](../rust/oauth.rs), [`OAuth.cs`](../csharp/OAuth.cs) and the [TypeScript submodule](../typescript/src/index.ts))
expose the same schema. Only the names differ for the submodule.

## Names

| | Rust / C# (flat) | TypeScript submodule mounted as `oauth` |
|---|---|---|
| View | `oauth_my_accounts` | `oauth.my_accounts` |
| Procedures | `oauth_begin`, `oauth_complete`, `oauth_unlink` | `oauth.begin`, `oauth.complete`, `oauth.unlink` |
| Route | `GET /route/oauth/callback` | the same (the consumer registers it) |

Arguments and results are identical. [`demo/web/src/api.ts`](../demo/web/src/api.ts) shows one client covering both.

## Procedures

Every procedure returns `Result<String, String>`, which clients see as `{ ok: string } | { err: string }`.

| Procedure | Arguments | `ok` |
|---|---|---|
| `oauth_begin` | `provider: String, scopes: String, return_to: String` | The provider's authorize URL |
| `oauth_complete` | `state: String, code: String` | The linked login |
| `oauth_unlink` | `provider: String` | The provider's name |

- `scopes` empty = the provider's configured defaults. Scopes are space-separated.
- `return_to` empty = **popup mode**. Otherwise **redirect mode**: it must start with an allowed app URL (`<base_url>/route/`
  or an `app_urls` entry).
- `oauth_complete` must be called by the identity that called `oauth_begin`. A state is single-use, and it expires after
  `state_ttl_secs`.

Errors you can expect from `oauth_complete`: `unknown or already used state`, `this link attempt belongs to another
identity`, `link attempt expired, start again`, `invalid_grant: …` (from the provider, e.g. a PKCE mismatch), and
`that <provider> account is already linked to another identity`.

## The view

`oauth_my_accounts` returns the caller's own accounts and never includes tokens:

| Field | Type | |
|---|---|---|
| `provider` | String | The config key, e.g. `twitch` |
| `external_id` | String | The provider's user id (stable) |
| `login` | String | Display login (from `login_path`) |
| `scopes` | String | Granted scopes, space-separated |
| `linked_at` | Timestamp | |
| `status` | String | `ok`, or `relink` when the provider rejected the refresh token |
| `expires_at` | Option\<Timestamp\> | Current access token's expiry |

## The authorize URL

```
<authorize_url>?response_type=code&client_id=…&redirect_uri=<base_url>/route/oauth/callback
  &state=<43 chars base64url>&code_challenge=<base64url(SHA-256(verifier))>&code_challenge_method=S256
  &scope=…[&<authorize_params>]
```

`state` and the PKCE `verifier` are `base64url(HMAC-SHA256(OAUTH_SECRET, "state|…" / "verifier|…"))` over the caller's
identity, the timestamp and a UUIDv7. The verifier never leaves the module.

## The callback

The provider redirects the browser to `GET <base_url>/route/oauth/callback?code=…&state=…` (or `?error=…&state=…`). The
module does **not** exchange the code here. It reads the pending attempt (and deletes it on a provider error), then:

**Redirect mode** (the attempt has a `return_to`): `302` to

```
<return_to>#oauth_state=…&oauth_code=…&oauth_provider=…      (or oauth_error=… instead of oauth_code)
```

The app reads the fragment (never sent to servers), clears it, and calls `oauth_complete(state, code)`.

**Popup mode**: a small HTML page that posts this to `window.opener`:

```json
{ "type": "spacetimedb-oauth", "state": "…", "provider": "mock", "code": "…" }
{ "type": "spacetimedb-oauth", "state": "…", "error": "access_denied: The user denied the request" }
```

It posts only to openers on allowed app URLs:

- **Same-origin opener** (the app is served from this database's routes): it reads `opener.location.href` and posts
  only if the URL starts with an allowed prefix. On a shared host like Maincloud, every database has the same origin, so
  the origin alone proves nothing.
- **Cross-origin opener** (your app on its own domain): it posts with `targetOrigin` set to each allowed URL's origin,
  so the browser only delivers to an opener on that origin.

The app should accept the message only from the callback's origin (the origin of `redirect_uri`) and only for the
`state` it started with, then call `oauth_complete`. [`client/src/index.ts`](../client/src/index.ts) does all of this.

## Tokens and refresh

- Token requests are `application/x-www-form-urlencoded` with `Accept: application/json`, client auth via
  `client_secret_post` (default) or `client_secret_basic` (`token_auth: "basic"`).
- `expires_in` sets the expiry. With a refresh token and `eager_refresh` (the default), a refresh is scheduled
  `min(refresh_margin_secs, lifetime / 5)` before expiry. A rotated refresh token replaces the old one.
- A refresh holds a 30 s lease, so concurrent callers don't both spend a rotating refresh token.
- `invalid_grant` (or any other 4xx except 408/429) on refresh is permanent: the token is deleted and the account becomes
  `relink`. Transient failures back off: 30 s, 1 min, 2 min, and so on, up to 8 tries.
- `with_token` / `get`: refresh first if the token expires within 30 s; on a 401, refresh once and retry.
- Unlink revokes at `revoke_url` (RFC 7009, best effort): the refresh token if there is one, else the access token.
