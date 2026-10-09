// Protocol tests: real clients and plain HTTP against a published oauth module and the mock
// provider. No browser.
//
//   DB=oauth-rust HOST=ws://127.0.0.1:3000 MOCK=http://127.0.0.1:4110 [FLAVOR=flat|ns] npx tsx tests/server.test.mts
//
// The module must be published with the mock provider configured as `mock` and
// `state_ttl_secs: 8` (scripts/e2e.sh does this). FLAVOR=ns for the TypeScript submodule.
import assert from 'node:assert/strict';
import { connect as connectApi, type Flavor, type OAuthApi } from '../demo/web/src/api.ts';

const HOST = process.env.HOST ?? 'ws://127.0.0.1:3000';
const HTTP = HOST.replace(/^ws/, 'http');
const DB = process.env.DB ?? 'oauth-rust';
const MOCK = process.env.MOCK ?? 'http://127.0.0.1:4110';
const FLAVOR = (process.env.FLAVOR ?? 'flat') as Flavor;
const BASE = `${HTTP}/v1/database/${DB}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const admin = async (path: string, body: object = {}) =>
  (await fetch(`${MOCK}/admin/${path}`, { method: path === 'stats' ? 'GET' : 'POST', body: path === 'stats' ? undefined : JSON.stringify(body) })).json();
const stats = async (): Promise<Record<string, number>> => admin('stats');

type Client = OAuthApi & { list: () => { provider: string; login: string; externalId: string; status: string; scopes: string }[] };

async function client(): Promise<Client> {
  const api = await connectApi(FLAVOR, HOST, DB);
  await new Promise<void>((res, rej) =>
    api.conn.subscriptionBuilder().onApplied(() => res()).onError((_c, e) => rej(e)).subscribe([`SELECT * FROM ${api.accountsSql}`])
  );
  return Object.assign(api, { list: () => [...api.accounts.iter()] as any[] });
}

/** Play the user at the provider: approve (as `user`) or deny, and follow the redirect to our callback. */
async function consent(authorizeUrl: string, user: string | null): Promise<URL> {
  const u = new URL(authorizeUrl);
  u.pathname = user ? '/authorize/approve' : '/authorize/deny';
  if (user) u.searchParams.set('user', user);
  const res = await fetch(u, { redirect: 'manual' });
  assert.equal(res.status, 302, `provider redirected (${res.status})`);
  return new URL(res.headers.get('location')!);
}

/** Begin, consent, and complete. Returns the linked account info. */
async function link(c: Client, user: string) {
  const cb = await consent(await c.begin('mock'), user);
  return c.complete(cb.searchParams.get('state')!, cb.searchParams.get('code')!);
}

const rejects = async (p: Promise<unknown>, re: RegExp) => {
  try {
    await p;
  } catch (e) {
    assert.match(String((e as Error).message), re);
    return;
  }
  assert.fail(`expected rejection matching ${re}`);
};

let passed = 0;
async function test(name: string, fn: () => Promise<void>) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

await admin('reset');
const a = await client();
const b = await client();
const PROFILE = `${MOCK}/api/me`;

await test('begin: an authorize URL with PKCE (S256), state and our callback; bad input rejected', async () => {
  const url = new URL(await a.begin('mock'));
  assert.equal(url.origin + url.pathname, `${MOCK}/authorize`);
  const q = url.searchParams;
  assert.equal(q.get('response_type'), 'code');
  assert.equal(q.get('client_id'), 'demo-client');
  assert.equal(q.get('redirect_uri'), `${BASE}/route/oauth/callback`);
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.match(q.get('code_challenge')!, /^[A-Za-z0-9_-]{43}$/);
  assert.match(q.get('state')!, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(q.get('scope'), 'profile api', 'provider default scopes');
  const other = new URL(await a.begin('mock', 'profile'));
  assert.notEqual(other.searchParams.get('state'), q.get('state'), 'fresh state each time');
  assert.equal(other.searchParams.get('scope'), 'profile');
  await rejects(a.begin('nope'), /unknown provider/);
  await rejects(a.begin('mock', '', 'https://evil.example/steal'), /not an allowed app URL/);
});

await test('link: consent → callback page hands over the code → complete; the view shows it to its owner only', async () => {
  const cb = await consent(await a.begin('mock'), 'alice');
  assert.equal(cb.origin + cb.pathname, `${BASE}/route/oauth/callback`);
  const page = await (await fetch(cb)).text();
  assert.ok(page.includes(cb.searchParams.get('code')!), 'page carries the code to the opener');
  assert.ok(page.includes(`${BASE}/route/`), 'page only hands it to allowed app URLs');
  assert.equal(await a.complete(cb.searchParams.get('state')!, cb.searchParams.get('code')!), 'alice');
  await sleep(150);
  const info = a.list()[0] as any;
  assert.equal(info.externalId, '1001');
  assert.equal(info.scopes, 'profile api');
  assert.ok(info.expiresAt, 'expiry known');
  assert.deepEqual(a.list().map((x) => [x.provider, x.login, x.status]), [['mock', 'alice', 'ok']]);
  assert.equal(b.list().length, 0, "b can't see a's accounts");
});

await test('tokens are private: no client can subscribe to the token or account tables', async () => {
  const ns = FLAVOR === 'ns' ? 'oauth.' : 'oauth_';
  for (const table of ['token', 'account', 'state']) {
    await rejects(
      new Promise<void>((res, rej) =>
        b.conn.subscriptionBuilder().onApplied(() => res()).onError((_c, e) => rej(e)).subscribe([`SELECT * FROM ${ns}${table}`])
      ),
      /private|no such table|not.*(found|exist)/i
    );
  }
});

await test('state is single-use', async () => {
  const cb = await consent(await a.begin('mock'), 'alice');
  await a.complete(cb.searchParams.get('state')!, cb.searchParams.get('code')!);
  await rejects(a.complete(cb.searchParams.get('state')!, cb.searchParams.get('code')!), /unknown or already used/);
});

await test("state is bound to its identity: another client can't complete it, the owner still can", async () => {
  const cb = await consent(await a.begin('mock'), 'alice');
  const [st, code] = [cb.searchParams.get('state')!, cb.searchParams.get('code')!];
  await rejects(b.complete(st, code), /belongs to another identity/);
  assert.equal(await a.complete(st, code), 'alice');
  assert.equal(b.list().length, 0);
});

await test('PKCE: a code only works with the verifier of the attempt it was issued for', async () => {
  const before = (await stats()).pkce_fail ?? 0;
  const first = await consent(await a.begin('mock'), 'alice');
  const second = new URL(await a.begin('mock')).searchParams.get('state')!;
  await rejects(a.complete(second, first.searchParams.get('code')!), /PKCE/);
  assert.equal((await stats()).pkce_fail, before + 1);
});

await test('provider error (Deny): the callback reports it and ends the attempt', async () => {
  const cb = await consent(await a.begin('mock'), null);
  assert.equal(cb.searchParams.get('error'), 'access_denied');
  const page = await (await fetch(cb)).text();
  assert.match(page, /access_denied/);
  await rejects(a.complete(cb.searchParams.get('state')!, 'whatever'), /unknown or already used/);
  const unknown = await (await fetch(`${BASE}/route/oauth/callback?state=nope&code=x`)).text();
  assert.match(unknown, /unknown or expired link attempt/);
});

await test('redirect mode: return_to gets the result in the URL fragment', async () => {
  const returnTo = `${BASE}/route/?after=link`;
  const cb = await consent(await a.begin('mock', '', returnTo), 'alice');
  const res = await fetch(cb, { redirect: 'manual' });
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get('location')!);
  assert.equal(loc.origin + loc.pathname + loc.search, returnTo);
  const frag = new URLSearchParams(loc.hash.slice(1));
  assert.equal(frag.get('oauth_provider'), 'mock');
  assert.equal(frag.get('oauth_state'), cb.searchParams.get('state'));
  assert.equal(await a.complete(frag.get('oauth_state')!, frag.get('oauth_code')!), 'alice');
});

await test('one external account, one identity: linking alice elsewhere is refused (and the new token revoked)', async () => {
  const revokes = (await stats()).revoke ?? 0;
  await rejects(link(b, 'alice'), /already linked to another identity/);
  assert.equal((await stats()).revoke, revokes + 1);
  assert.equal(b.list().length, 0);
});

await test('with_token: API calls work, and a token the provider expired early is refreshed and retried', async () => {
  const profile = JSON.parse(await a.profile('mock', PROFILE));
  assert.equal(profile.preferred_username, 'alice');
  const refreshes = (await stats()).token_refresh ?? 0;
  await admin('expire', { user: 'alice' });
  const again = JSON.parse(await a.profile('mock', PROFILE));
  assert.equal(again.preferred_username, 'alice');
  assert.equal((await stats()).token_refresh, refreshes + 1, 'one refresh, then the retry succeeded');
  await rejects(b.profile('mock', PROFILE), /no linked mock account/);
});

await test('scheduled refresh: tokens are renewed ahead of expiry with no calls in between', async () => {
  await admin('config', { ttl: 6 });
  await link(a, 'alice'); // a 6 s token: refresh is scheduled ~1.2 s before it expires
  const before = (await stats()).token_refresh ?? 0;
  await admin('config', { ttl: 3600 }); // the refreshed token lives long, so refreshing stops
  await sleep(6500);
  assert.equal((await stats()).token_refresh, before + 1, 'refreshed once, on schedule');
  await sleep(1000);
  const refreshes = (await stats()).token_refresh;
  JSON.parse(await a.profile('mock', PROFILE)); // the 6 s token has expired by now; the refreshed one works
  assert.equal((await stats()).token_refresh, refreshes, 'no extra refresh needed');
});

await test('revoked at the provider: refresh fails for good, the account is marked for relinking', async () => {
  await admin('revoke', { user: 'alice' });
  await rejects(a.profile('mock', PROFILE), /invalid_grant/);
  await sleep(150);
  assert.equal(a.list()[0].status, 'relink');
  await rejects(a.profile('mock', PROFILE), /needs to be linked again/);
  assert.equal(await link(a, 'alice'), 'alice');
  await sleep(150);
  assert.equal(a.list()[0].status, 'ok', 'relinking fixes it');
});

await test('unlink: the account and tokens are deleted and the grant is revoked at the provider', async () => {
  assert.equal(await link(b, 'bob'), 'bob');
  const revokes = (await stats()).revoke ?? 0;
  await b.unlink('mock');
  assert.equal((await stats()).revoke, revokes + 1);
  await sleep(150);
  assert.equal(b.list().length, 0);
  await rejects(b.profile('mock', PROFILE), /no linked mock account/);
  await rejects(b.unlink('mock'), /no linked mock account/);
});

await test('link attempts expire (state_ttl_secs)', async () => {
  const cb = await consent(await a.begin('mock'), 'alice');
  await sleep(8500);
  await rejects(a.complete(cb.searchParams.get('state')!, cb.searchParams.get('code')!), /expired/);
});

console.log(`\n${passed} passed`);
await a.unlink('mock'); // leave alice free for the browser tests
for (const c of [a, b]) c.conn.disconnect();
process.exit(0);
