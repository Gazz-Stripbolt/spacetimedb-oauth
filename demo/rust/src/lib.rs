//! Demo: link an account at a (mock) OAuth provider, see it, call its API, unlink it.
//! Serves the web client at `/route/`.

#[path = "../../../rust/oauth.rs"]
pub mod oauth;

use http::{StatusCode, header};
use spacetimedb::ProcedureContext;
use spacetimedb::http::{Body, HandlerContext, Request, Response, Router, handler, router};

const PAGE: &str = include_str!("../../web/dist/index.html");

/// Call the provider's API as the caller: its profile endpoint (the mock's `/api/me`, or the
/// provider's userinfo). Shows `oauth::get` refreshing and retrying behind the scenes.
#[spacetimedb::procedure]
pub fn demo_profile(
    ctx: &mut ProcedureContext,
    provider: String,
    url: String,
) -> Result<String, String> {
    let who = ctx.sender();
    let (status, body) = oauth::get(ctx, who, &provider, &url)?;
    if status >= 400 {
        return Err(format!("{status}: {body}"));
    }
    Ok(body)
}

#[handler]
fn page(_ctx: &mut HandlerContext, _req: Request) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_bytes(PAGE))
        .unwrap()
}

#[router]
fn routes() -> Router {
    oauth::router().get("/", page)
}
