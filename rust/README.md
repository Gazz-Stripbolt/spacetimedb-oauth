# oauth.rs: account linking for Rust modules

One file. Copy [`oauth.rs`](oauth.rs) to your module's `src/oauth.rs`, then:

```toml
# Cargo.toml (HTTP handlers need `unstable`)
spacetimedb = { version = "2.11.*", features = ["unstable"] }
http = "1"
serde_json = "1"
sha2 = "0.10"
hmac = "0.12"
log = "0.4"
```

```rust
pub mod oauth;

#[spacetimedb::http::router]
fn router() -> spacetimedb::http::Router { oauth::router() }   // or .merge() it into yours
```

Set `OAUTH_CONFIG` and `OAUTH_SECRET` when you publish ([configuration](../README.md#configuration)). `oauth.rs`
declares them in its own `#[spacetimedb::env]` struct. If your module already has one, move the two fields there.

A complete module is in [`demo/rust`](../demo/rust/src/lib.rs).

## What you get

**Client procedures:** `oauth_begin`, `oauth_complete`, `oauth_unlink`. **Public view:** `oauth_my_accounts`.
**Route:** `GET /route/oauth/callback`. See [PROTOCOL.md](../docs/PROTOCOL.md).

**Library functions** for your own procedures and reducers:

| Function | |
|---|---|
| `get(ctx, who, provider, url) -> Result<(u16, String)>` | GET a provider API as `who`: bearer token, API headers, refresh-and-retry |
| `with_token(ctx, who, provider, \|ctx, token\| -> Result<Response>)` | Any request with a valid token. Refreshes when the token is about to expire, and once on a 401 |
| `unlink(ctx, who, provider)` | Delete the account and revoke its grant |
| `linked_account(tx, who, provider) -> Option<OauthAccount>` | From reducers too: who `who` is at `provider` |
| `parse_config(raw)` | The parsed `OAUTH_CONFIG`, if you need provider details |

```rust
#[spacetimedb::procedure]
pub fn my_follows(ctx: &mut ProcedureContext) -> Result<String, String> {
    let me = ctx.sender();
    let (status, body) = oauth::get(ctx, me, "twitch", "https://api.twitch.tv/helix/channels/followed?user_id=…")?;
    if status >= 400 { return Err(body); }
    Ok(body)
}
```
