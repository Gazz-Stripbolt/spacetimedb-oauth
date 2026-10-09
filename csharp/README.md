# OAuth.cs: account linking for C# modules

One file. Add [`OAuth.cs`](OAuth.cs) to your module project (or link it, like
[`demo/csharp/StdbModule.csproj`](../demo/csharp/StdbModule.csproj) does), and add the callback route:

```csharp
[SpacetimeDB.HttpRouter]
public static Router Routes() => OauthRoutes(Router.New());
```

Set `OAUTH_CONFIG` and `OAUTH_SECRET` when you publish ([configuration](../README.md#configuration)). `OAuth.cs`
declares them in its own `[SpacetimeDB.Env]` struct. If your module already has one, move the two fields there.

A complete module is in [`demo/csharp`](../demo/csharp/Lib.cs). It builds with NativeAOT-LLVM (.NET 10). No
`System.Security.Cryptography` on wasi, so a small managed SHA-256/HMAC is included.

## What you get

The same procedures, view and route as Rust (`oauth_begin`, `oauth_complete`, `oauth_unlink`, `oauth_my_accounts`;
see [PROTOCOL.md](../docs/PROTOCOL.md)). C# canonicalises to the same names, so the same clients work with both.

| Function | |
|---|---|
| `OauthGet(ctx, who, provider, url) → (ushort Status, string Body)` | GET a provider API as `who`, with refresh-and-retry |
| `OauthWithToken(ctx, who, provider, token => HttpResponse)` | Any request with a valid token |
| `OauthUnlinkAccount(ctx, who, provider)` | Delete the account and revoke its grant |
| `OauthLinkedAccount(db, who, provider) → OauthAccount?` | From reducers too |
| `OauthParseConfig(raw)` | The parsed `OAUTH_CONFIG` |

The procedures return `Result<string, string>` ([why](../docs/FINDINGS.md#bug-the-ts-sdk-serializes-result-errors-with-the-ok-type)).
