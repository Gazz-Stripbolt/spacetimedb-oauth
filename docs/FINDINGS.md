# Findings

What we learned building OAuth account linking on SpacetimeDB 2.11: the security model, the platform's quirks, and
two TypeScript SDK bugs.

## Security model

**Who is linking?** The classic account-linking attack goes like this. The attacker starts a link for *their*
identity, sends the victim the authorize URL, and the victim (already signed in at the provider) consents. If the
callback exchanged the code itself, the victim's Twitch account would now belong to the attacker's identity. So the
callback never redeems anything. It hands `state` + `code` to the app, and the app calls `oauth_complete` over its own
SpacetimeDB connection, where the module can check that `ctx.sender` is the identity that began. In the phishing
scenario the code lands in the victim's browser, and only the attacker could redeem the state.

**PKCE everywhere.** The code is useless without the verifier, which never leaves the module. A test checks that a
code issued for one attempt can't be completed with another attempt's verifier.

**Don't use the module RNG alone for secrets.** Module randomness is deterministic. So the state and verifier are
`HMAC-SHA256(OAUTH_SECRET, identity | timestamp | uuidv7)`: unique per attempt and unpredictable without the env secret.

**Maincloud is one origin.** Every database's HTTP routes live on `maincloud.spacetimedb.com`. `postMessage`'s
`targetOrigin` can't be narrowed to a path, and cookies, `localStorage` and `BroadcastChannel` on that origin are shared
with every other database. Any of those would leak the code to whatever page another database serves. Instead, the
callback page reads `window.opener.location.href` (allowed, since it's same-origin) and posts only when it starts with
an allowed app URL (`<base_url>/route/` by default). A browser test opens the flow from another path on the same origin
and checks it receives nothing.

**Tokens stay private.** Accounts, tokens and pending states are private tables. Clients get a **view**
(`oauth_my_accounts`) filtered by `ctx.sender`. That's much simpler than RLS: views can read private tables, and it
needs none of the event-table RLS gymnastics from [spacetimedb-voip](https://github.com/Gazz-Stripbolt/spacetimedb-voip).
A test checks that subscribing to the token, account or state tables is refused.

## SpacetimeDB quirks

- **HTTP handlers *can* make outbound requests** (`ctx.http` exists on `HandlerContext`). We deliberately don't use it
  in the callback, because finishing on the client's connection is the security property above. The token exchange
  runs in a procedure.
- **No HTTP inside a transaction.** Procedures do HTTP between `with_tx` calls, never inside them. The C# runtime notes
  the host rejects it (`WOULD_BLOCK_TRANSACTION`). So every flow is read/claim in one transaction, HTTP, then write in
  another, and refresh uses a lease column so two procedures don't refresh the same token at once.
- **`with_tx` bodies may run more than once.** Keep them deterministic: compute randomness (the state) outside,
  and pass it in.
- **Routes have no path parameters.** There's one callback (`/oauth/callback`) for all providers; the pending state says
  which provider it was.
- **One env declaration per module.** The Rust and C# drop-ins declare `OAUTH_CONFIG` and `OAUTH_SECRET`. If your
  module already has an env struct, move the two fields into it. Submodules can't read env at all, so the TS consumer
  passes them to `configure()`, which stores them in a private table (re-run after `publish --env-only`).
- **Submodule views keep their canonical name on the client:** `conn.db['oauth.my_accounts']`, while submodule
  procedures get camel-cased accessors (`conn.procedures['oauth.begin']`).
- **C# and Rust canonicalise to the same schema** once the C# names are written `Oauth…`, not `OAuth…`.
  `OAuthMyAccounts` would canonicalise to `o_auth_my_accounts`.

## Bug: the TS SDK serializes `Result` errors with the `ok` type (reported: [#6122](https://github.com/clockworklabs/SpacetimeDB/issues/6122))

In `spacetimedb` 2.11 (`src/lib/algebraic_type.ts`, the `ok`/`err` sum serializer):

```ts
const serializeOk  = AlgebraicType.makeSerializer(ty.variants[0].algebraicType, typespace);
const serializeErr = AlgebraicType.makeSerializer(ty.variants[0].algebraicType, typespace);  // should be variants[1]
```

So a TS procedure (or reducer/view) returning `t.result(A, B)` with `A ≠ B` crashes the moment it returns an `err`. We hit
`TypeError: Cannot read properties of undefined (reading 'length')` in `writeString` for `t.result(AccountInfo, t.string())`,
and the instance reported a fatal error. `t.result(t.string(), t.string())` works by accident. That's why every
procedure in all three languages returns `Result<String, String>`, since they share one schema. The fix is a one-character
change (`variants[1]`).

## Bug: `t.result()` is typed `Ok | Err`, but the runtime wants `{ ok } | { err }` (reported: [#6127](https://github.com/clockworklabs/SpacetimeDB/issues/6127))

`ResultBuilder<Ok, Err>` infers its value type as `InferTypeOfTypeBuilder<Ok> | InferTypeOfTypeBuilder<Err>`, but
the serializer (above) expects an object with an `ok` or `err` key. Returning `{ ok: … }` from a procedure therefore
needs a cast. With the type as written, there's no way to tell `ok` from `err` when both are strings.

## Browser side

- **Open the popup synchronously** (inside the click), then navigate it once `oauth_begin` returns. Popup blockers
  reject `window.open` after an `await`.
- **Watch for the user closing the popup** (`popup.closed` polling). Otherwise the app waits forever.
- **COOP can cut the popup off.** If a provider's pages send `Cross-Origin-Opener-Policy: same-origin`, the popup loses
  `window.opener` for good, even after it navigates back to our callback. The page then says "Return to the app", and
  redirect mode is the fallback. This hasn't been tried against the real providers yet; the tests use the mock.
- **Redirect mode has to keep the identity.** The page that comes back must use the same SpacetimeDB token as the one
  that started, or `oauth_complete` is (rightly) refused. The demo keeps its token in `localStorage`.
