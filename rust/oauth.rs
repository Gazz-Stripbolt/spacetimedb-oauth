//! # oauth.rs: link OAuth accounts to SpacetimeDB identities, and keep their tokens fresh
//!
//! Copy this file to your module's `src/oauth.rs`, add `pub mod oauth;` to `lib.rs`, enable the
//! `unstable` feature on `spacetimedb` (HTTP handlers need it), add the dependencies below, set
//! two env vars, and register the callback route:
//!
//! ```toml
//! spacetimedb = { version = "2.11.*", features = ["unstable"] }
//! http = "1"
//! serde_json = "1"
//! sha2 = "0.10"
//! hmac = "0.12"
//! ```
//!
//! ```ignore
//! #[spacetimedb::http::router]
//! fn router() -> Router { oauth::router() }
//! ```
//!
//! What it gives you:
//!
//! - **Account linking** with the authorization code flow and PKCE (S256). The client calls the
//!   `oauth_begin` procedure for an authorize URL, the provider redirects to this module's
//!   `/route/oauth/callback`, and the client finishes with `oauth_complete`, so the identity that
//!   links is the one authenticated on the client's own connection.
//! - **A token vault.** Access and refresh tokens live in private tables. Clients see only the
//!   `oauth_my_accounts` view: their own provider, external id, login and scopes.
//! - **Fresh tokens.** A scheduled procedure refreshes tokens ahead of expiry, and
//!   [`with_token`] refreshes on demand and retries once on a 401.
//! - **Presets** for Twitch, Discord, Google, GitHub and Spotify, plus any OAuth 2.0 provider.
//!
//! Configuration is owner-only by construction: it comes from env vars.

use hmac::{Hmac, Mac};
use http::{StatusCode, header};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use spacetimedb::http::{Body, HandlerContext, Request, Response, Router, Timeout, handler};
use spacetimedb::{
    Identity, ProcedureContext, ScheduleAt, SpacetimeType, Table, TimeDuration, Timestamp,
    TxContext, ViewContext,
};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Owner-set configuration. If your module already declares an env struct, move these two
/// fields into it and delete this one (a module has one env declaration).
#[spacetimedb::env]
pub struct Env {
    /// JSON: `{"base_url": "https://host/v1/database/<db>", "providers": {...}, ...}`.
    /// See the README for every key.
    pub OAUTH_CONFIG: String,
    /// A long random string. Keys the state and PKCE verifiers, so they can't be predicted.
    pub OAUTH_SECRET: String,
}

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// A refresh in progress holds this lease, so concurrent callers don't rotate the token twice.
const REFRESH_LEASE: Duration = Duration::from_secs(30);
/// Pending link attempts per identity. Older ones are dropped.
const MAX_PENDING: usize = 5;
const MAX_REFRESH_FAILURES: u32 = 8;

/// The parsed `OAUTH_CONFIG`.
#[derive(Clone, Debug)]
pub struct Config {
    /// `https://host/v1/database/<db>`, used to build the redirect URI.
    pub base_url: String,
    /// URL prefixes allowed to receive the result (popup opener, or `return_to`).
    pub app_urls: Vec<String>,
    pub state_ttl_secs: u64,
    pub refresh_margin_secs: u64,
    pub providers: Vec<Provider>,
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub revoke_url: String,
    pub userinfo_url: String,
    /// Dotted path into the userinfo JSON, e.g. `data.0.id`.
    pub id_path: String,
    pub login_path: String,
    pub scopes: String,
    /// `post` (client_secret_post) or `basic` (client_secret_basic).
    pub token_auth: String,
    pub authorize_params: Vec<(String, String)>,
    /// Extra headers on userinfo and `get` calls. `{client_id}` is substituted.
    pub api_headers: Vec<(String, String)>,
    /// Refresh on a schedule ahead of expiry (`true`), or only when a token is used.
    pub eager_refresh: bool,
}

/// Built-in provider settings. Anything can be overridden in `OAUTH_CONFIG`.
fn preset(name: &str) -> Value {
    match name {
        "twitch" => json!({
            "authorize_url": "https://id.twitch.tv/oauth2/authorize",
            "token_url": "https://id.twitch.tv/oauth2/token",
            "revoke_url": "https://id.twitch.tv/oauth2/revoke",
            "userinfo_url": "https://api.twitch.tv/helix/users",
            "id_path": "data.0.id", "login_path": "data.0.login",
            "api_headers": { "Client-Id": "{client_id}" },
        }),
        "discord" => json!({
            "authorize_url": "https://discord.com/oauth2/authorize",
            "token_url": "https://discord.com/api/oauth2/token",
            "revoke_url": "https://discord.com/api/oauth2/token/revoke",
            "userinfo_url": "https://discord.com/api/users/@me",
            "id_path": "id", "login_path": "username", "scopes": "identify",
        }),
        "google" => json!({
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "revoke_url": "https://oauth2.googleapis.com/revoke",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "id_path": "sub", "login_path": "email", "scopes": "openid email profile",
            // Ask for a refresh token every time.
            "authorize_params": { "access_type": "offline", "prompt": "consent" },
        }),
        "github" => json!({
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "id_path": "id", "login_path": "login", "scopes": "read:user",
        }),
        "spotify" => json!({
            "authorize_url": "https://accounts.spotify.com/authorize",
            "token_url": "https://accounts.spotify.com/api/token",
            "userinfo_url": "https://api.spotify.com/v1/me",
            "id_path": "id", "login_path": "display_name", "scopes": "user-read-private",
            "token_auth": "basic",
        }),
        _ => json!({ "id_path": "sub", "login_path": "preferred_username" }),
    }
}

pub fn parse_config(raw: &str) -> Result<Config, String> {
    let v: Value =
        serde_json::from_str(raw).map_err(|e| format!("OAUTH_CONFIG is not JSON: {e}"))?;
    let base_url = v["base_url"]
        .as_str()
        .ok_or("OAUTH_CONFIG.base_url is required")?
        .trim_end_matches('/')
        .to_string();
    let mut app_urls = vec![format!("{base_url}/route/")];
    if let Some(list) = v["app_urls"].as_array() {
        app_urls.extend(list.iter().filter_map(|u| u.as_str()).map(String::from));
    }
    let mut providers = Vec::new();
    for (name, over) in v["providers"]
        .as_object()
        .ok_or("OAUTH_CONFIG.providers is required")?
    {
        let mut merged = preset(over["preset"].as_str().unwrap_or(name));
        for (k, val) in over
            .as_object()
            .ok_or("provider config must be an object")?
        {
            merged[k] = val.clone();
        }
        let s = |k: &str| merged[k].as_str().unwrap_or_default().to_string();
        let pairs = |k: &str| -> Vec<(String, String)> {
            merged[k]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(a, b)| (a.clone(), b.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };
        let p = Provider {
            name: name.clone(),
            client_id: s("client_id"),
            client_secret: s("client_secret"),
            authorize_url: s("authorize_url"),
            token_url: s("token_url"),
            revoke_url: s("revoke_url"),
            userinfo_url: s("userinfo_url"),
            id_path: s("id_path"),
            login_path: s("login_path"),
            scopes: s("scopes"),
            token_auth: if s("token_auth") == "basic" {
                "basic".into()
            } else {
                "post".into()
            },
            authorize_params: pairs("authorize_params"),
            api_headers: pairs("api_headers"),
            eager_refresh: merged["eager_refresh"].as_bool().unwrap_or(true),
        };
        for (field, val) in [
            ("client_id", &p.client_id),
            ("authorize_url", &p.authorize_url),
            ("token_url", &p.token_url),
            ("userinfo_url", &p.userinfo_url),
        ] {
            if val.is_empty() {
                return Err(format!("provider `{name}` is missing `{field}`"));
            }
        }
        providers.push(p);
    }
    Ok(Config {
        base_url,
        app_urls,
        state_ttl_secs: v["state_ttl_secs"].as_u64().unwrap_or(600),
        refresh_margin_secs: v["refresh_margin_secs"].as_u64().unwrap_or(300),
        providers,
    })
}

impl Config {
    pub fn provider(&self, name: &str) -> Result<&Provider, String> {
        self.providers
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| format!("unknown provider `{name}`"))
    }
    pub fn redirect_uri(&self) -> String {
        format!("{}/route/oauth/callback", self.base_url)
    }
    fn allowed(&self, url: &str) -> bool {
        self.app_urls.iter().any(|p| url.starts_with(p.as_str()))
    }
}

fn config(env: &spacetimedb::Environment) -> Result<(Config, String), String> {
    Ok((parse_config(&env.OAUTH_CONFIG())?, env.OAUTH_SECRET()))
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// A link attempt in progress: single-use, short-lived, bound to the identity that started it.
#[spacetimedb::table(accessor = oauth_state)]
#[derive(Clone)]
pub struct OauthState {
    #[primary_key]
    pub state: String,
    #[index(btree)]
    pub identity: Identity,
    pub provider: String,
    pub verifier: String,
    pub scopes: String,
    pub return_to: String,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

/// A linked account. Private: clients read their own through `oauth_my_accounts`.
#[spacetimedb::table(
    accessor = oauth_account,
    index(accessor = by_external, btree(columns = [provider, external_id]))
)]
#[derive(Clone)]
pub struct OauthAccount {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub identity: Identity,
    pub provider: String,
    pub external_id: String,
    pub login: String,
    pub scopes: String,
    pub linked_at: Timestamp,
    /// `ok`, or `relink` when the provider stopped accepting the refresh token.
    pub status: String,
    pub last_error: String,
}

/// The secrets. Private, never exposed by any view.
#[spacetimedb::table(accessor = oauth_token)]
#[derive(Clone)]
pub struct OauthToken {
    #[primary_key]
    pub account_id: u64,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub refreshed_at: Timestamp,
    pub refreshing_until: Option<Timestamp>,
    pub refresh_failures: u32,
}

#[spacetimedb::table(accessor = oauth_refresh_job, scheduled(oauth_refresh_due))]
pub struct OauthRefreshJob {
    #[primary_key]
    #[auto_inc]
    pub scheduled_id: u64,
    pub scheduled_at: ScheduleAt,
    #[index(btree)]
    pub account_id: u64,
}

/// What a client may know about its own linked accounts.
#[derive(SpacetimeType, Clone, Debug, PartialEq)]
pub struct OauthAccountInfo {
    pub provider: String,
    pub external_id: String,
    pub login: String,
    pub scopes: String,
    pub linked_at: Timestamp,
    pub status: String,
    pub expires_at: Option<Timestamp>,
}

impl OauthAccountInfo {
    fn of(a: &OauthAccount, t: Option<&OauthToken>) -> Self {
        Self {
            provider: a.provider.clone(),
            external_id: a.external_id.clone(),
            login: a.login.clone(),
            scopes: a.scopes.clone(),
            linked_at: a.linked_at,
            status: a.status.clone(),
            expires_at: t.and_then(|t| t.expires_at),
        }
    }
}

/// The caller's linked accounts. Never includes tokens.
#[spacetimedb::view(accessor = oauth_my_accounts, public)]
pub fn oauth_my_accounts(ctx: &ViewContext) -> Vec<OauthAccountInfo> {
    ctx.db
        .oauth_account()
        .identity()
        .filter(ctx.sender())
        .map(|a| {
            let t = ctx.db.oauth_token().account_id().find(a.id);
            OauthAccountInfo::of(&a, t.as_ref())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Client procedures
// ---------------------------------------------------------------------------

/// Start linking: returns the provider's authorize URL. `scopes` empty = the provider's
/// defaults. `return_to` empty = popup mode (the callback page messages the opener);
/// otherwise the browser is redirected there with `#oauth_state=..&oauth_code=..`.
#[spacetimedb::procedure]
pub fn oauth_begin(
    ctx: &mut ProcedureContext,
    provider: String,
    scopes: String,
    return_to: String,
) -> Result<String, String> {
    let (cfg, secret) = config(&ctx.env)?;
    let p = cfg.provider(&provider)?.clone();
    let scopes = if scopes.trim().is_empty() {
        p.scopes.clone()
    } else {
        scopes.trim().to_string()
    };
    if scopes.chars().any(|c| c.is_control() || c == '"') {
        return Err("bad scopes".into());
    }
    if !return_to.is_empty() && !cfg.allowed(&return_to) {
        return Err("return_to is not an allowed app URL".into());
    }
    let who = ctx.sender();
    let nonce = ctx.new_uuid_v7().map_err(|e| e.to_string())?.to_string();
    let seed = format!(
        "{who}|{}|{nonce}",
        ctx.timestamp.to_micros_since_unix_epoch()
    );
    let state = b64url(&hmac(&secret, &format!("state|{seed}")));
    let verifier = b64url(&hmac(&secret, &format!("verifier|{seed}")));
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let row = OauthState {
        state: state.clone(),
        identity: who,
        provider: provider.clone(),
        verifier,
        scopes: scopes.clone(),
        return_to,
        created_at: ctx.timestamp,
        expires_at: ctx.timestamp + Duration::from_secs(cfg.state_ttl_secs),
    };
    ctx.with_tx(|tx| {
        // Housekeeping: expired attempts, and all but the newest few for this identity.
        let expired: Vec<String> = tx
            .db
            .oauth_state()
            .iter()
            .filter(|s| s.expires_at < tx.timestamp)
            .map(|s| s.state)
            .collect();
        for s in expired {
            tx.db.oauth_state().state().delete(&s);
        }
        let mut mine: Vec<OauthState> = tx.db.oauth_state().identity().filter(who).collect();
        mine.sort_by_key(|s| s.created_at);
        for s in mine
            .iter()
            .take((mine.len() + 1).saturating_sub(MAX_PENDING))
        {
            tx.db.oauth_state().state().delete(&s.state);
        }
        tx.db.oauth_state().insert(row.clone());
    });
    let mut q = vec![
        ("response_type", "code".to_string()),
        ("client_id", p.client_id.clone()),
        ("redirect_uri", cfg.redirect_uri()),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
    ];
    if !scopes.is_empty() {
        q.push(("scope", scopes));
    }
    let mut url = format!(
        "{}{}{}",
        p.authorize_url,
        if p.authorize_url.contains('?') {
            "&"
        } else {
            "?"
        },
        form(&q)
    );
    for (k, v) in &p.authorize_params {
        url.push_str(&format!("&{}={}", enc(k), enc(v)));
    }
    Ok(url)
}

/// Finish linking with the `state` and `code` the callback page handed back. Only the identity
/// that called `oauth_begin` can complete it. Returns the linked login; `oauth_my_accounts` has
/// the details.
///
/// (Every procedure here returns `Result<String, String>`: the TypeScript submodule can't return
/// a `Result` whose two sides differ in 2.11, and all three languages share one schema.)
#[spacetimedb::procedure]
pub fn oauth_complete(
    ctx: &mut ProcedureContext,
    state: String,
    code: String,
) -> Result<String, String> {
    complete(ctx, state, code).map(|a| a.login)
}

fn complete(
    ctx: &mut ProcedureContext,
    state: String,
    code: String,
) -> Result<OauthAccountInfo, String> {
    let (cfg, _) = config(&ctx.env)?;
    let who = ctx.sender();
    let pending = ctx.with_tx(|tx| -> Result<OauthState, String> {
        let s = tx
            .db
            .oauth_state()
            .state()
            .find(&state)
            .ok_or("unknown or already used state")?;
        if s.identity != who {
            return Err("this link attempt belongs to another identity".into());
        }
        tx.db.oauth_state().state().delete(&state);
        if s.expires_at < tx.timestamp {
            return Err("link attempt expired, start again".into());
        }
        Ok(s)
    })?;
    let p = cfg.provider(&pending.provider)?.clone();
    let tokens = token_request(
        ctx,
        &p,
        &[
            ("grant_type", "authorization_code".into()),
            ("code", code),
            ("redirect_uri", cfg.redirect_uri()),
            ("code_verifier", pending.verifier.clone()),
        ],
    )
    .map_err(|e| e.message)?;
    let access = tokens["access_token"]
        .as_str()
        .ok_or("no access_token in token response")?
        .to_string();
    let (external_id, login) = match userinfo(ctx, &p, &access) {
        Ok(x) => x,
        Err(e) => {
            revoke(ctx, &p, &access);
            return Err(e);
        }
    };
    let scopes = scopes_of(&tokens).unwrap_or(pending.scopes.clone());
    let now = ctx.timestamp;
    let expires_at = expires_at_of(&tokens, now);
    let refresh_token = tokens["refresh_token"].as_str().map(String::from);
    let margin = cfg.refresh_margin_secs;
    let eager = p.eager_refresh;
    let linked = ctx.with_tx(|tx| -> Result<OauthAccountInfo, String> {
        let taken = tx
            .db
            .oauth_account()
            .by_external()
            .filter((p.name.as_str(), external_id.as_str()))
            .any(|a| a.identity != who);
        if taken {
            return Err(format!(
                "that {} account is already linked to another identity",
                p.name
            ));
        }
        // One account per provider per identity: re-linking replaces the old one.
        if let Some(old) = find_account(tx, who, &p.name) {
            delete_account(tx, old.id);
        }
        let a = tx.db.oauth_account().insert(OauthAccount {
            id: 0,
            identity: who,
            provider: p.name.clone(),
            external_id: external_id.clone(),
            login: login.clone(),
            scopes: scopes.clone(),
            linked_at: tx.timestamp,
            status: "ok".into(),
            last_error: String::new(),
        });
        let t = tx.db.oauth_token().insert(OauthToken {
            account_id: a.id,
            access_token: access.clone(),
            refresh_token: refresh_token.clone(),
            expires_at,
            refreshed_at: tx.timestamp,
            refreshing_until: None,
            refresh_failures: 0,
        });
        if eager {
            schedule_refresh(tx, &t, margin);
        }
        Ok(OauthAccountInfo::of(&a, Some(&t)))
    });
    if linked.is_err() {
        revoke(ctx, &p, &access);
    }
    linked
}

/// Unlink the caller's account for `provider`, revoking its tokens at the provider (best effort).
/// Returns the provider's name.
#[spacetimedb::procedure]
pub fn oauth_unlink(ctx: &mut ProcedureContext, provider: String) -> Result<String, String> {
    let who = ctx.sender();
    unlink(ctx, who, &provider).map(|()| provider)
}

// ---------------------------------------------------------------------------
// Library API: call these from your own procedures
// ---------------------------------------------------------------------------

/// Run `call` with a valid access token for `who`'s `provider` account. Refreshes first if the
/// token is about to expire, and once more (then retries) if `call` gets a 401.
pub fn with_token(
    ctx: &mut ProcedureContext,
    who: Identity,
    provider: &str,
    mut call: impl FnMut(&mut ProcedureContext, &str) -> Result<Response, String>,
) -> Result<Response, String> {
    let (account_id, mut access, expires_at, can_refresh) =
        ctx.with_tx(|tx| -> Result<_, String> {
            let a = find_account(tx, who, provider)
                .ok_or_else(|| format!("no linked {provider} account"))?;
            if a.status != "ok" {
                return Err(format!("the {provider} account needs to be linked again"));
            }
            let t = tx
                .db
                .oauth_token()
                .account_id()
                .find(a.id)
                .ok_or("no token")?;
            Ok((
                a.id,
                t.access_token,
                t.expires_at,
                t.refresh_token.is_some(),
            ))
        })?;
    if can_refresh && expires_at.is_some_and(|e| e < ctx.timestamp + Duration::from_secs(30)) {
        access = refresh(ctx, account_id)?;
    }
    let response = call(ctx, &access)?;
    if response.status() != StatusCode::UNAUTHORIZED || !can_refresh {
        return Ok(response);
    }
    access = refresh(ctx, account_id)?;
    call(ctx, &access)
}

/// GET `url` as `who`'s `provider` account (bearer token plus the provider's API headers).
/// Returns the status and body.
pub fn get(
    ctx: &mut ProcedureContext,
    who: Identity,
    provider: &str,
    url: &str,
) -> Result<(u16, String), String> {
    let (cfg, _) = config(&ctx.env)?;
    let p = cfg.provider(provider)?.clone();
    let url = url.to_string();
    let response = with_token(ctx, who, provider, |ctx, token| {
        ctx.http
            .send(api_request(&p, &url, token)?)
            .map_err(|e| e.to_string())
    })?;
    let status = response.status().as_u16();
    Ok((status, response.into_body().into_string_lossy()))
}

/// Unlink `who`'s `provider` account and revoke its tokens (best effort).
pub fn unlink(ctx: &mut ProcedureContext, who: Identity, provider: &str) -> Result<(), String> {
    let (cfg, _) = config(&ctx.env)?;
    let token = ctx.with_tx(|tx| -> Result<Option<OauthToken>, String> {
        let a = find_account(tx, who, provider)
            .ok_or_else(|| format!("no linked {provider} account"))?;
        let t = tx.db.oauth_token().account_id().find(a.id);
        delete_account(tx, a.id);
        Ok(t)
    })?;
    if let (Some(t), Ok(p)) = (token, cfg.provider(provider)) {
        let p = p.clone();
        revoke(
            ctx,
            &p,
            t.refresh_token.as_deref().unwrap_or(&t.access_token),
        );
    }
    Ok(())
}

/// Who `who` is at `provider`, if linked: `(external_id, login)`. Works in reducers too.
pub fn linked_account(tx: &TxContext, who: Identity, provider: &str) -> Option<OauthAccount> {
    find_account(tx, who, provider)
}

/// The callback route. Merge into your module's router.
pub fn router() -> Router {
    Router::new().get("/oauth/callback", oauth_callback)
}

// ---------------------------------------------------------------------------
// Callback and refresh
// ---------------------------------------------------------------------------

/// The provider redirects the browser here. No tokens are handled: the page hands `state` and
/// `code` to the app (popup opener, or `return_to`), which calls `oauth_complete`.
#[handler]
pub fn oauth_callback(ctx: &mut HandlerContext, req: Request) -> Response {
    let q = parse_query(req.uri().query().unwrap_or_default());
    let get = |k: &str| {
        q.iter()
            .find(|(a, _)| a == k)
            .map(|(_, b)| b.clone())
            .unwrap_or_default()
    };
    let (state, code, error) = (get("state"), get("code"), get("error"));
    let cfg = match parse_config(&ctx.env.OAUTH_CONFIG()) {
        Ok(c) => c,
        Err(e) => {
            return html(
                StatusCode::INTERNAL_SERVER_ERROR,
                &result_page(&json!({ "error": e }), &[]),
            );
        }
    };
    let pending = ctx.with_tx(|tx| {
        let s = tx.db.oauth_state().state().find(&state);
        // A provider-side error (e.g. the user clicked Deny) ends this attempt.
        if s.is_some() && !error.is_empty() {
            tx.db.oauth_state().state().delete(&state);
        }
        s
    });
    let mut msg = Map::new();
    msg.insert("type".into(), "spacetimedb-oauth".into());
    msg.insert("state".into(), state.clone().into());
    if let Some(s) = &pending {
        msg.insert("provider".into(), s.provider.clone().into());
    }
    if !error.is_empty() {
        let desc = get("error_description");
        msg.insert(
            "error".into(),
            if desc.is_empty() {
                error
            } else {
                format!("{error}: {desc}")
            }
            .into(),
        );
    } else if pending.is_none() {
        msg.insert("error".into(), "unknown or expired link attempt".into());
    } else {
        msg.insert("code".into(), code.into());
    }
    // Redirect mode: hand the result to the app in the URL fragment (never sent to servers).
    if let Some(s) = pending.filter(|s| !s.return_to.is_empty()) {
        let frag: Vec<(&str, String)> = msg
            .iter()
            .filter(|(k, _)| k.as_str() != "type")
            .map(|(k, v)| (k.as_str(), v.as_str().unwrap_or_default().to_string()))
            .map(|(k, v)| match k {
                "state" => ("oauth_state", v),
                "code" => ("oauth_code", v),
                "error" => ("oauth_error", v),
                _ => ("oauth_provider", v),
            })
            .collect();
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, format!("{}#{}", s.return_to, form(&frag)))
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::empty())
            .unwrap();
    }
    html(
        StatusCode::OK,
        &result_page(&Value::Object(msg), &cfg.app_urls),
    )
}

/// Scheduled: refresh a token ahead of its expiry.
#[spacetimedb::procedure]
pub fn oauth_refresh_due(ctx: &mut ProcedureContext, job: OauthRefreshJob) {
    if let Err(e) = refresh(ctx, job.account_id) {
        log::info!(
            "oauth: scheduled refresh of account {}: {e}",
            job.account_id
        );
    }
}

/// Refresh `account_id`'s token now. Returns the new access token.
fn refresh(ctx: &mut ProcedureContext, account_id: u64) -> Result<String, String> {
    let (cfg, _) = config(&ctx.env)?;
    let lease = ctx.timestamp + REFRESH_LEASE;
    let (provider, refresh_token) = ctx.with_tx(|tx| -> Result<(String, String), String> {
        let a = tx
            .db
            .oauth_account()
            .id()
            .find(account_id)
            .ok_or("account is gone")?;
        let mut t = tx
            .db
            .oauth_token()
            .account_id()
            .find(account_id)
            .ok_or("token is gone")?;
        let rt = t.refresh_token.clone().ok_or("no refresh token")?;
        if t.refreshing_until.is_some_and(|u| u > tx.timestamp) {
            return Err("a refresh is already in progress, try again shortly".into());
        }
        t.refreshing_until = Some(lease);
        tx.db.oauth_token().account_id().update(t);
        Ok((a.provider, rt))
    })?;
    let p = cfg.provider(&provider)?.clone();
    let result = token_request(
        ctx,
        &p,
        &[
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh_token),
        ],
    );
    let margin = cfg.refresh_margin_secs;
    let eager = p.eager_refresh;
    ctx.with_tx(|tx| -> Result<String, String> {
        let a = tx
            .db
            .oauth_account()
            .id()
            .find(account_id)
            .ok_or("account is gone")?;
        let mut t = tx
            .db
            .oauth_token()
            .account_id()
            .find(account_id)
            .ok_or("token is gone")?;
        t.refreshing_until = None;
        clear_jobs(tx, account_id);
        match &result {
            Ok(tokens) => {
                let access = tokens["access_token"]
                    .as_str()
                    .ok_or("no access_token in refresh response")?;
                t.access_token = access.to_string();
                if let Some(rt) = tokens["refresh_token"].as_str() {
                    t.refresh_token = Some(rt.to_string());
                }
                t.expires_at = expires_at_of(tokens, tx.timestamp);
                t.refreshed_at = tx.timestamp;
                t.refresh_failures = 0;
                if let Some(scopes) = scopes_of(tokens) {
                    tx.db
                        .oauth_account()
                        .id()
                        .update(OauthAccount { scopes, ..a });
                }
                let t = tx.db.oauth_token().account_id().update(t);
                if eager {
                    schedule_refresh(tx, &t, margin);
                }
                Ok(t.access_token)
            }
            Err(e) if e.permanent => {
                // The grant is gone (revoked, expired): the user has to link again.
                tx.db.oauth_token().account_id().delete(account_id);
                tx.db.oauth_account().id().update(OauthAccount {
                    status: "relink".into(),
                    last_error: e.message.clone(),
                    ..a
                });
                Err(e.message.clone())
            }
            Err(e) => {
                t.refresh_failures += 1;
                let retry = t.refresh_failures <= MAX_REFRESH_FAILURES;
                let backoff = Duration::from_secs(15u64 << t.refresh_failures.min(8));
                tx.db.oauth_account().id().update(OauthAccount {
                    last_error: e.message.clone(),
                    ..a
                });
                tx.db.oauth_token().account_id().update(t);
                if retry {
                    tx.db.oauth_refresh_job().insert(OauthRefreshJob {
                        scheduled_id: 0,
                        scheduled_at: ScheduleAt::Time(tx.timestamp + backoff),
                        account_id,
                    });
                }
                Err(e.message.clone())
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

struct TokenError {
    message: String,
    /// The provider refused the grant (`invalid_grant`): retrying won't help.
    permanent: bool,
}

fn token_request(
    ctx: &mut ProcedureContext,
    p: &Provider,
    params: &[(&str, String)],
) -> Result<Value, TokenError> {
    let mut params: Vec<(&str, String)> = params.to_vec();
    let mut builder = http::Request::builder()
        .method("POST")
        .uri(&p.token_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .extension(Timeout::from(TimeDuration::from_duration(HTTP_TIMEOUT)));
    if p.token_auth == "basic" {
        let creds = format!("{}:{}", enc(&p.client_id), enc(&p.client_secret));
        builder = builder.header(
            header::AUTHORIZATION,
            format!("Basic {}", b64(creds.as_bytes())),
        );
    } else {
        params.push(("client_id", p.client_id.clone()));
        params.push(("client_secret", p.client_secret.clone()));
    }
    let transient = |m: String| TokenError {
        message: m,
        permanent: false,
    };
    let request = builder
        .body(form(&params))
        .map_err(|e| transient(e.to_string()))?;
    let response = ctx
        .http
        .send(request)
        .map_err(|e| transient(format!("token endpoint: {e}")))?;
    let status = response.status();
    let text = response.into_body().into_string_lossy();
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if status.is_success() && body["access_token"].is_string() {
        return Ok(body);
    }
    let error = body["error"].as_str().unwrap_or_default();
    let desc = body["error_description"].as_str().unwrap_or_default();
    let short: String = text.chars().take(200).collect();
    Err(TokenError {
        message: if error.is_empty() {
            format!("token endpoint: {} {short}", status.as_u16())
        } else {
            format!("{error}: {desc}")
        },
        permanent: error == "invalid_grant"
            || (status.is_client_error()
                && status != StatusCode::TOO_MANY_REQUESTS
                && status != StatusCode::REQUEST_TIMEOUT),
    })
}

fn api_request(p: &Provider, url: &str, token: &str) -> Result<Request, String> {
    let mut b = http::Request::builder()
        .method("GET")
        .uri(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "spacetimedb-oauth")
        .extension(Timeout::from(TimeDuration::from_duration(HTTP_TIMEOUT)));
    for (k, v) in &p.api_headers {
        b = b.header(k.as_str(), v.replace("{client_id}", &p.client_id));
    }
    b.body(Body::empty()).map_err(|e| e.to_string())
}

fn userinfo(
    ctx: &mut ProcedureContext,
    p: &Provider,
    token: &str,
) -> Result<(String, String), String> {
    let response = ctx
        .http
        .send(api_request(p, &p.userinfo_url, token)?)
        .map_err(|e| format!("userinfo: {e}"))?;
    let status = response.status();
    let text = response.into_body().into_string_lossy();
    if !status.is_success() {
        return Err(format!(
            "userinfo: {} {}",
            status.as_u16(),
            text.chars().take(200).collect::<String>()
        ));
    }
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("userinfo is not JSON: {e}"))?;
    let id = at_path(&v, &p.id_path).ok_or_else(|| format!("userinfo has no `{}`", p.id_path))?;
    let login = at_path(&v, &p.login_path).unwrap_or_default();
    Ok((id, login))
}

/// Revoke a token at the provider, if it supports revocation. Best effort.
fn revoke(ctx: &mut ProcedureContext, p: &Provider, token: &str) {
    if p.revoke_url.is_empty() {
        return;
    }
    let mut params = vec![("token", token.to_string())];
    let mut b = http::Request::builder()
        .method("POST")
        .uri(&p.revoke_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .extension(Timeout::from(TimeDuration::from_duration(HTTP_TIMEOUT)));
    if p.token_auth == "basic" {
        let creds = format!("{}:{}", enc(&p.client_id), enc(&p.client_secret));
        b = b.header(
            header::AUTHORIZATION,
            format!("Basic {}", b64(creds.as_bytes())),
        );
    } else {
        params.push(("client_id", p.client_id.clone()));
        params.push(("client_secret", p.client_secret.clone()));
    }
    if let Ok(req) = b.body(form(&params))
        && let Err(e) = ctx.http.send(req)
    {
        log::info!("oauth: revoke at {}: {e}", p.name);
    }
}

fn find_account(tx: &TxContext, who: Identity, provider: &str) -> Option<OauthAccount> {
    tx.db
        .oauth_account()
        .identity()
        .filter(who)
        .find(|a| a.provider == provider)
}

fn delete_account(tx: &TxContext, account_id: u64) {
    clear_jobs(tx, account_id);
    tx.db.oauth_token().account_id().delete(account_id);
    tx.db.oauth_account().id().delete(account_id);
}

fn clear_jobs(tx: &TxContext, account_id: u64) {
    let jobs: Vec<u64> = tx
        .db
        .oauth_refresh_job()
        .account_id()
        .filter(account_id)
        .map(|j| j.scheduled_id)
        .collect();
    for id in jobs {
        tx.db.oauth_refresh_job().scheduled_id().delete(id);
    }
}

/// Refresh `margin` before expiry (at most a fifth of the token's lifetime early).
fn schedule_refresh(tx: &TxContext, t: &OauthToken, margin_secs: u64) {
    let (Some(exp), Some(_)) = (t.expires_at, &t.refresh_token) else {
        return;
    };
    let life = exp.to_micros_since_unix_epoch() - tx.timestamp.to_micros_since_unix_epoch();
    let early = (margin_secs as i64 * 1_000_000).min(life / 5).max(0);
    let at = Timestamp::from_micros_since_unix_epoch(
        (exp.to_micros_since_unix_epoch() - early).max(tx.timestamp.to_micros_since_unix_epoch()),
    );
    tx.db.oauth_refresh_job().insert(OauthRefreshJob {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Time(at),
        account_id: t.account_id,
    });
}

fn expires_at_of(tokens: &Value, now: Timestamp) -> Option<Timestamp> {
    let secs = match &tokens["expires_in"] {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }?;
    (secs > 0.0).then(|| now + Duration::from_secs_f64(secs))
}

/// Granted scopes, space-separated (Twitch returns an array).
fn scopes_of(tokens: &Value) -> Option<String> {
    match &tokens["scope"] {
        Value::String(s) => Some(s.replace(',', " ")),
        Value::Array(a) => Some(
            a.iter()
                .filter_map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    }
}

/// `data.0.id` style lookup; numbers come back as strings.
fn at_path(v: &Value, path: &str) -> Option<String> {
    let mut cur = v;
    for part in path.split('.').filter(|p| !p.is_empty()) {
        cur = match part.parse::<usize>() {
            Ok(i) if cur.is_array() => cur.get(i)?,
            _ => cur.get(part)?,
        };
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn hmac(secret: &str, msg: &str) -> Vec<u8> {
    let mut m =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac takes any key length");
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64url(bytes: &[u8]) -> String {
    b64(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Percent-encode everything but RFC 3986 unreserved characters.
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn form(params: &[(&str, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    let dec = |s: &str| {
        let b = s.replace('+', " ").into_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && i + 2 < b.len()
                && let Ok(h) =
                    u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
            {
                out.push(h);
                i += 3;
                continue;
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (dec(k), dec(v))
        })
        .collect()
}

fn html(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header("referrer-policy", "no-referrer")
        .body(Body::from_bytes(body.to_string()))
        .unwrap()
}

/// The page the provider redirects to. It hands the result to the window that opened it, but
/// only if that window is an allowed app URL (same-origin openers are checked by full URL
/// prefix, so another app on a shared host can't receive it).
fn result_page(msg: &Value, allowed: &[String]) -> String {
    let data = msg.to_string().replace('<', "\\u003c");
    let allowed = serde_json::to_string(allowed)
        .unwrap_or_default()
        .replace('<', "\\u003c");
    RESULT_PAGE
        .replace("/*MSG*/null", &data)
        .replace("/*ALLOWED*/[]", &allowed)
}

const RESULT_PAGE: &str = r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linking account</title>
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
</script></body></html>"#;
