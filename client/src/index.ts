/**
 * # spacetimedb-oauth-client: the browser side of linking
 *
 * Opens the provider in a popup, waits for the callback page to hand back `state` and `code`,
 * and finishes with your module's `oauth_complete` procedure on your own connection. That
 * last step is what proves who is linking. Also handles redirect mode (no popup).
 *
 * Not tied to your generated bindings: you pass the two procedure calls in.
 *
 * ```ts
 * const unwrap = async (p) => { const r = await p; if ('err' in r) throw new Error(r.err); return r.ok; };
 * button.onclick = () =>
 *   linkAccount({
 *     provider: 'twitch',
 *     begin: (provider, scopes, returnTo) => unwrap(conn.procedures.oauthBegin({ provider, scopes, returnTo })),
 *     complete: (state, code) => unwrap(conn.procedures.oauthComplete({ state, code })),
 *   }).then((login) => console.log('linked as', login));
 * ```
 */

export interface LinkOptions {
  provider: string;
  /** Scopes to request; '' (default) uses the provider's configured defaults. */
  scopes?: string;
  /** Your `oauth_begin` procedure: resolve to the authorize URL, reject on error. */
  begin: (provider: string, scopes: string, returnTo: string) => Promise<string>;
  /** Your `oauth_complete` procedure: resolve to the linked login, reject on error. */
  complete: (state: string, code: string) => Promise<string>;
  /** Popup size. Default 520 x 680. */
  width?: number;
  height?: number;
  /** Give up after this long. Default 10 minutes. */
  timeoutMs?: number;
}

/** What the module's callback page posts to the opener. */
export interface CallbackMessage {
  type: 'spacetimedb-oauth';
  state: string;
  provider?: string;
  code?: string;
  error?: string;
}

/**
 * Link an account in a popup. Call it from a click handler (popup blockers allow popups only
 * from user gestures). Resolves to the linked login.
 *
 * The callback page lives on the database's host, so messages are accepted only from the origin
 * of the authorize URL's `redirect_uri`.
 */
export async function linkAccount(o: LinkOptions): Promise<string> {
  const w = o.width ?? 520;
  const h = o.height ?? 680;
  const left = Math.max(0, (screen.width - w) / 2);
  const top = Math.max(0, (screen.height - h) / 2);
  // Open synchronously (inside the click), then point it at the provider once we have the URL.
  const popup = window.open('', 'spacetimedb-oauth', `popup,width=${w},height=${h},left=${left},top=${top}`);
  if (!popup) throw new Error('the popup was blocked; allow popups for this site and try again');
  let url: string;
  try {
    url = await o.begin(o.provider, o.scopes ?? '', '');
  } catch (e) {
    popup.close();
    throw e;
  }
  const callbackOrigin = new URL(new URL(url).searchParams.get('redirect_uri') ?? location.href).origin;
  const state = new URL(url).searchParams.get('state');
  popup.location.href = url;

  const msg = await new Promise<CallbackMessage>((resolve, reject) => {
    const done = (f: () => void) => {
      removeEventListener('message', onMessage);
      clearInterval(closed);
      clearTimeout(timer);
      f();
    };
    const onMessage = (e: MessageEvent) => {
      const m = e.data as CallbackMessage;
      if (e.origin !== callbackOrigin || m?.type !== 'spacetimedb-oauth' || m.state !== state) return;
      done(() => resolve(m));
    };
    addEventListener('message', onMessage);
    // A user who closes the popup gets a clear error instead of a hang.
    const closed = setInterval(() => popup.closed && done(() => reject(new Error('the sign-in window was closed'))), 500);
    const timer = setTimeout(() => done(() => reject(new Error('timed out waiting for the provider'))), o.timeoutMs ?? 600_000);
  });
  if (msg.error) throw new Error(msg.error);
  return o.complete(msg.state, msg.code!);
}

/**
 * Redirect mode: send the whole page to the provider. Pass `returnTo` (an allowed app URL,
 * usually the current page); the module redirects back there with the result in the fragment.
 * On load, call `completeFromRedirect` to finish.
 */
export async function linkByRedirect(o: Omit<LinkOptions, 'complete'> & { returnTo?: string }): Promise<never> {
  location.assign(await o.begin(o.provider, o.scopes ?? '', o.returnTo ?? location.href.split('#')[0]));
  return new Promise(() => {});
}

/**
 * If this page was reached by a redirect-mode callback, finish linking and clean the URL.
 * Resolves to `null` when there's nothing to finish, else to the linked login (or rejects).
 */
export async function completeFromRedirect(complete: LinkOptions['complete']): Promise<string | null> {
  const frag = new URLSearchParams(location.hash.slice(1));
  const state = frag.get('oauth_state');
  if (!state) return null;
  history.replaceState(null, '', location.pathname + location.search);
  const error = frag.get('oauth_error');
  if (error) throw new Error(error);
  return complete(state, frag.get('oauth_code') ?? '');
}
