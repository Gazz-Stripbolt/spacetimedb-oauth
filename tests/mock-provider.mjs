// A mock OAuth 2.0 provider for tests and the demo: authorization code + PKCE (S256),
// refresh tokens (rotated), revocation (RFC 7009), userinfo, and a protected API.
// No dependencies. Never use it for anything real.
//
//   node tests/mock-provider.mjs [--port 4110]
//
// Client: demo-client / demo-secret. Users: alice, bob, carol.
// Admin endpoints for tests: POST /admin/config {ttl, rotate}, POST /admin/expire {user},
// POST /admin/revoke {user}, GET /admin/stats, POST /admin/reset.
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';

const CLIENTS = { 'demo-client': 'demo-secret' };
const USERS = {
  alice: { sub: '1001', preferred_username: 'alice', name: 'Alice Archer' },
  bob: { sub: '1002', preferred_username: 'bob', name: 'Bob Baker' },
  carol: { sub: '1003', preferred_username: 'carol', name: 'Carol Cooper' },
};

export function createMockProvider() {
  let settings = { ttl: 3600, rotate: true };
  let codes = new Map();
  let access = new Map();
  let refresh = new Map();
  let stats = {};
  const bump = (k) => (stats[k] = (stats[k] ?? 0) + 1);
  const now = () => Date.now() / 1000;
  const token = (p) => `${p}_${randomBytes(18).toString('base64url')}`;

  function json(res, status, body, headers = {}) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(body));
  }
  function redirect(res, url) {
    res.writeHead(302, { location: url });
    res.end();
  }
  function readBody(req) {
    return new Promise((resolve) => {
      let b = '';
      req.on('data', (c) => (b += c));
      req.on('end', () => resolve(b));
    });
  }
  /** client_secret_post or client_secret_basic. */
  function clientAuth(req, form) {
    let id = form.get('client_id');
    let secret = form.get('client_secret');
    const auth = req.headers.authorization ?? '';
    if (auth.startsWith('Basic ')) {
      const [u, p] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
      id = decodeURIComponent(u);
      secret = decodeURIComponent(p ?? '');
    }
    return id && CLIENTS[id] === secret ? id : null;
  }
  function issue(user, client, scope) {
    const grant = token('grant');
    const a = token('at');
    access.set(a, { user, client, scope, grant, exp: now() + settings.ttl, revoked: false });
    const r = token('rt');
    refresh.set(r, { user, client, scope, grant, revoked: false });
    return { access_token: a, token_type: 'bearer', expires_in: settings.ttl, refresh_token: r, scope };
  }
  function bearer(req) {
    const m = /^Bearer (.+)$/i.exec(req.headers.authorization ?? '');
    const t = m && access.get(m[1]);
    return t && !t.revoked && t.exp > now() ? t : null;
  }
  function authorizeError(q) {
    if (q.get('response_type') !== 'code') return 'response_type must be code';
    if (!CLIENTS[q.get('client_id')]) return 'unknown client_id';
    if (!q.get('redirect_uri')?.startsWith('http')) return 'bad redirect_uri';
    if (!q.get('state')) return 'state is required';
    if (!q.get('code_challenge') || q.get('code_challenge_method') !== 'S256') return 'PKCE (S256) is required';
    return null;
  }

  const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#f4f1ec;color:#1d1c1a;display:grid;place-items:center;min-height:100vh}
.card{background:#fff;border:1px solid #e2ddd3;border-radius:14px;padding:28px 30px;width:min(360px,90vw);box-shadow:0 8px 30px rgba(0,0,0,.06)}
h1{font-size:19px;margin:0 0 4px}p{color:#6b6862;margin:0 0 18px}a.u{display:flex;gap:10px;align-items:center;padding:10px 12px;border:1px solid #e2ddd3;border-radius:10px;margin-bottom:8px;color:inherit;text-decoration:none}
a.u:hover{background:#f7f5f1}.av{width:30px;height:30px;border-radius:50%;background:#6d5bd0;color:#fff;display:grid;place-items:center;font-weight:600;font-size:13px}
.deny{display:block;text-align:center;margin-top:12px;color:#9a3412}.scope{font-family:ui-monospace,monospace;font-size:13px;background:#f4f1ec;padding:1px 6px;border-radius:5px}</style></head><body><div class="card">${body}</div></body></html>`;

  async function handle(req, res) {
    const url = new URL(req.url, 'http://mock');
    const q = url.searchParams;
    const path = url.pathname;

    if (req.method === 'GET' && path === '/authorize') {
      bump('authorize');
      const err = authorizeError(q);
      if (err) return json(res, 400, { error: 'invalid_request', error_description: err });
      const users = Object.entries(USERS)
        .map(([u, info]) => `<a class="u" href="/authorize/approve?${q}&user=${u}"><span class="av">${u[0].toUpperCase()}</span><span><b>${info.name}</b><br><small>@${u}</small></span></a>`)
        .join('');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(page('Mock Provider', `<h1>Mock Provider</h1><p>Sign in to link your account. Requested scopes: <span class="scope">${(q.get('scope') || '(none)').replace(/[<&]/g, '')}</span></p>${users}<a class="deny" href="/authorize/deny?${q}">Deny</a>`));
    }
    if (req.method === 'GET' && (path === '/authorize/approve' || path === '/authorize/deny')) {
      const err = authorizeError(q);
      if (err) return json(res, 400, { error: 'invalid_request', error_description: err });
      const back = new URL(q.get('redirect_uri'));
      back.searchParams.set('state', q.get('state'));
      if (path === '/authorize/deny') {
        back.searchParams.set('error', 'access_denied');
        back.searchParams.set('error_description', 'The user denied the request');
        return redirect(res, back.toString());
      }
      const user = q.get('user');
      if (!USERS[user]) return json(res, 400, { error: 'invalid_request', error_description: 'unknown user' });
      const code = token('code');
      codes.set(code, {
        client: q.get('client_id'),
        redirect_uri: q.get('redirect_uri'),
        challenge: q.get('code_challenge'),
        user,
        scope: q.get('scope') ?? '',
        exp: now() + 60,
        used: false,
      });
      back.searchParams.set('code', code);
      return redirect(res, back.toString());
    }
    if (req.method === 'POST' && path === '/token') {
      const form = new URLSearchParams(await readBody(req));
      const client = clientAuth(req, form);
      if (!client) return json(res, 401, { error: 'invalid_client' });
      const grant = form.get('grant_type');
      if (grant === 'authorization_code') {
        bump('token_code');
        const c = codes.get(form.get('code') ?? '');
        if (!c || c.used || c.exp < now() || c.client !== client) return json(res, 400, { error: 'invalid_grant', error_description: 'bad or used code' });
        c.used = true;
        if (c.redirect_uri !== form.get('redirect_uri')) return json(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
        const verifier = form.get('code_verifier') ?? '';
        if (createHash('sha256').update(verifier).digest('base64url') !== c.challenge) {
          bump('pkce_fail');
          return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
        }
        return json(res, 200, issue(c.user, client, c.scope));
      }
      if (grant === 'refresh_token') {
        bump('token_refresh');
        const rt = form.get('refresh_token') ?? '';
        const r = refresh.get(rt);
        if (!r || r.revoked || r.client !== client) return json(res, 400, { error: 'invalid_grant', error_description: 'bad refresh token' });
        const a = token('at');
        access.set(a, { user: r.user, client, scope: r.scope, grant: r.grant, exp: now() + settings.ttl, revoked: false });
        const out = { access_token: a, token_type: 'bearer', expires_in: settings.ttl, scope: r.scope };
        if (settings.rotate) {
          r.revoked = true;
          const nr = token('rt');
          refresh.set(nr, { ...r, revoked: false });
          out.refresh_token = nr;
        }
        return json(res, 200, out);
      }
      return json(res, 400, { error: 'unsupported_grant_type' });
    }
    if (req.method === 'POST' && path === '/revoke') {
      bump('revoke');
      const form = new URLSearchParams(await readBody(req));
      if (!clientAuth(req, form)) return json(res, 401, { error: 'invalid_client' });
      const t = form.get('token') ?? '';
      const r = refresh.get(t) ?? access.get(t);
      if (r) {
        // Revoking either token ends the whole grant (that sign-in), as real providers do.
        for (const m of [access, refresh]) for (const v of m.values()) if (v.grant === r.grant) v.revoked = true;
      }
      res.writeHead(200);
      return res.end();
    }
    if (req.method === 'GET' && (path === '/userinfo' || path === '/api/me')) {
      bump(path === '/userinfo' ? 'userinfo' : 'api');
      const t = bearer(req);
      if (!t) return json(res, 401, { error: 'invalid_token' }, { 'www-authenticate': 'Bearer error="invalid_token"' });
      const u = USERS[t.user];
      return json(res, 200, path === '/userinfo' ? u : { ...u, scope: t.scope, calls: stats.api });
    }

    // -- admin (tests) --
    if (path === '/admin/stats') return json(res, 200, stats);
    if (req.method === 'POST' && path.startsWith('/admin/')) {
      const body = JSON.parse((await readBody(req)) || '{}');
      if (path === '/admin/config') {
        settings = { ...settings, ...body };
      } else if (path === '/admin/expire') {
        for (const t of access.values()) if (!body.user || t.user === body.user) t.exp = 0;
      } else if (path === '/admin/revoke') {
        for (const m of [access, refresh]) for (const v of m.values()) if (!body.user || v.user === body.user) v.revoked = true;
      } else if (path === '/admin/reset') {
        settings = { ttl: 3600, rotate: true };
        codes = new Map();
        access = new Map();
        refresh = new Map();
        stats = {};
      } else {
        return json(res, 404, { error: 'not found' });
      }
      return json(res, 200, { ok: true, settings });
    }
    json(res, 404, { error: 'not found' });
  }

  return createServer((req, res) =>
    handle(req, res).catch((e) => {
      console.error(e);
      json(res, 500, { error: 'server_error' });
    })
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const i = process.argv.indexOf('--port');
  const port = i > 0 ? Number(process.argv[i + 1]) : Number(process.env.MOCK_PORT ?? 4110);
  createMockProvider().listen(port, '127.0.0.1', () => console.log(`mock OAuth provider on http://127.0.0.1:${port}`));
}
