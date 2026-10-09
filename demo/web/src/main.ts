// Demo web client: link a Mock Provider account, see it, call its API, unlink it.
// Served by the demo module at /route/, or open dist/index.html with ?host=ws://...&db=...
import { linkAccount, linkByRedirect, completeFromRedirect } from 'spacetimedb-oauth-client';
import { connect, type Flavor, type OAuthApi } from './api';

const params = new URLSearchParams(location.search);
const routed = location.pathname.match(/\/v1\/database\/([^/]+)\/route/);
const HOST = params.get('host') ?? (routed ? location.origin.replace(/^http/, 'ws') : 'ws://127.0.0.1:3000');
const DB = params.get('db') ?? (routed ? decodeURIComponent(routed[1]) : 'oauth-rust');
// Schema flavour: 'flat' (Rust, C#) or 'ns' (TypeScript submodule). The TS demo module serves
// this page with data-flavor="ns"; for a static copy, pass ?flavor=ns.
const FLAVOR = (params.get('flavor') ?? document.documentElement.dataset.flavor ?? 'flat') as Flavor;
/** The mock provider's protected API, called through the module with the linked token. */
const API = params.get('api') ?? 'http://127.0.0.1:4110/api/me';
const PROVIDER = 'mock';
const TOKEN_KEY = `oauth-demo:${HOST}:${DB}`;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const el = (tag: string, cls = '', text = '') => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
};

function log(text: string, detail = '', err = false) {
  const row = el('div', 'e' + (err ? ' err' : ''));
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  row.append(`${time}  `, el('b', '', text), detail ? `  ${detail}` : '');
  $('log').prepend(row);
}

function status(text: string, ok = true) {
  $('status').textContent = text;
  $('status').classList.toggle('bad', !ok);
}

const stored = () => {
  // ?fresh=1 starts with a new identity, except when coming back from a redirect-mode link,
  // which has to finish as the identity that started it.
  if (params.has('fresh') && !location.hash.includes('oauth_state')) return undefined;
  try {
    return localStorage.getItem(TOKEN_KEY) ?? undefined;
  } catch {
    return undefined;
  }
};

let api: OAuthApi;
try {
  api = await connect(FLAVOR, HOST, DB, stored(), () => status('disconnected', false));
} catch (e) {
  status(`can't connect: ${e}`, false);
  throw e;
}
try {
  localStorage.setItem(TOKEN_KEY, api.token);
} catch {}
if (params.has('test')) Object.assign(window, { __api: api });
status(`connected to ${DB}`);
$('me').textContent = `identity ${api.identity.toHexString().slice(0, 12)}…`;

api.accounts.onInsert(render);
api.accounts.onDelete(render);
api.conn.subscriptionBuilder().onApplied(render).subscribe([`SELECT * FROM ${api.accountsSql}`]);

const fmtExpiry = (micros?: bigint) => {
  if (micros === undefined) return 'no expiry';
  const s = Math.round((Number(micros / 1000n) - Date.now()) / 1000);
  if (s <= 0) return 'expired';
  return s > 3600 ? `refreshes in ~${Math.round(s / 3600)} h` : s > 90 ? `refreshes in ~${Math.round(s / 60)} min` : `refreshes in ${s} s`;
};

function render() {
  const list = $('accounts');
  list.replaceChildren();
  const rows = [...api.accounts.iter()];
  if (!rows.length) list.append(el('div', 'empty', 'Nothing linked yet.'));
  for (const a of rows) {
    const row = el('div', 'account');
    row.dataset.provider = a.provider;
    const who = el('div');
    const name = el('div', 'who', a.login || a.externalId);
    name.append(el('span', `badge ${a.status}`, a.status === 'ok' ? 'linked' : 'needs relinking'));
    const meta = el('div', 'meta');
    meta.innerHTML = `${a.provider} · id <code></code> · scopes <code></code> · <span></span>`;
    const [idc, scc] = meta.querySelectorAll('code');
    idc.textContent = a.externalId;
    scc.textContent = a.scopes || '(none)';
    meta.querySelector('span')!.textContent = a.status === 'ok' ? fmtExpiry(a.expiresAt?.microsSinceUnixEpoch) : 'the provider revoked access';
    who.append(name, meta);
    const actions = el('div', 'actions');
    const call = el('button', 'btn small', 'Call API') as HTMLButtonElement;
    call.onclick = () => callApi(a.provider);
    const unlink = el('button', 'btn small danger', 'Unlink') as HTMLButtonElement;
    unlink.onclick = async () => {
      try {
        await api.unlink(a.provider);
        log('unlinked', a.provider);
      } catch (e) {
        log('unlink failed', String((e as Error).message), true);
      }
    };
    if (a.status === 'ok') actions.append(call);
    actions.append(unlink);
    row.append(el('div', 'avatar', (a.login || a.provider).slice(0, 1).toUpperCase()), who, actions);
    list.append(row);
  }
}
setInterval(render, 15_000);

async function callApi(provider: string) {
  $('api-panel').hidden = false;
  $('api-title').textContent = `GET ${API}`;
  try {
    const body = await api.profile(provider, API);
    $('api').textContent = JSON.stringify(JSON.parse(body), null, 2);
    log('API call', `200 from ${provider}`);
  } catch (e) {
    $('api').textContent = String((e as Error).message);
    log('API call failed', String((e as Error).message), true);
  }
}

const opts = {
  provider: PROVIDER,
  begin: (provider: string, scopes: string, returnTo: string) => api.begin(provider, scopes, returnTo),
  complete: (state: string, code: string) => api.complete(state, code),
};

$('link').onclick = async () => {
  const b = $<HTMLButtonElement>('link');
  b.disabled = true;
  log('linking', 'opened the provider in a popup');
  try {
    const login = await linkAccount(opts);
    log('linked', `${PROVIDER} as ${login}`);
  } catch (e) {
    log('link failed', String((e as Error).message), true);
  } finally {
    b.disabled = false;
  }
};
$('link-redirect').onclick = () => {
  log('linking', 'redirecting to the provider');
  linkByRedirect(opts).catch((e) => log('link failed', String((e as Error).message), true));
};

// Coming back from a redirect-mode link?
completeFromRedirect(opts.complete)
  .then((login) => login && log('linked', `${PROVIDER} as ${login} (redirect mode)`))
  .catch((e) => log('link failed', String((e as Error).message), true));
