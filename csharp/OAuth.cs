// OAuth.cs: link OAuth accounts to SpacetimeDB identities, and keep their tokens fresh.
//
// The C# twin of rust/oauth.rs and the spacetimedb-oauth TypeScript submodule. Same tables,
// procedures and callback route, so the same clients work against all three.
//
// Drop this file into your module project, set OAUTH_CONFIG and OAUTH_SECRET, and add the
// callback route to your router:
//
//     [SpacetimeDB.HttpRouter]
//     public static Router Routes() => OauthRoutes(Router.New());
//
// Linking is the authorization code flow with PKCE. The client calls oauth_begin for an
// authorize URL, the provider redirects to /route/oauth/callback, and the client finishes with
// oauth_complete, so the identity that links is the one authenticated on its own connection.
// Tokens live in private tables; clients see only the oauth_my_accounts view. A scheduled
// procedure refreshes tokens ahead of expiry, and OauthWithToken refreshes on demand and
// retries once on a 401.

#pragma warning disable STDB_UNSTABLE
#nullable enable

using System.Text;
using System.Text.Json.Nodes;
using SpacetimeDB;
using HttpMethod = SpacetimeDB.HttpMethod;

/// <summary>What a client may know about its own linked accounts.</summary>
[SpacetimeDB.Type]
public partial struct OauthAccountInfo
{
    public string Provider;
    public string ExternalId;
    public string Login;
    public string Scopes;
    public Timestamp LinkedAt;
    public string Status;
    public Timestamp? ExpiresAt;
}

public static partial class Module
{
    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /// <summary>
    /// Owner-set configuration. If your module already declares a [SpacetimeDB.Env] struct,
    /// move these two fields into it and delete this one (a module has one env declaration).
    /// </summary>
    [SpacetimeDB.Env]
    public partial struct OauthEnvironment
    {
        /// <summary>JSON: {"base_url": "https://host/v1/database/&lt;db&gt;", "providers": {...}}</summary>
        public string OAUTH_CONFIG;
        /// <summary>A long random string. Keys the state and PKCE verifiers.</summary>
        public string OAUTH_SECRET;
    }

    static ModuleEnvironment OauthEnv => default;

    static readonly TimeSpan OauthHttpTimeout = TimeSpan.FromSeconds(10);
    const long OauthLeaseUs = 30L * 1_000_000;
    const int OauthMaxPending = 5;
    const uint OauthMaxRefreshFailures = 8;
    static long oauthNonce;

    public sealed record OauthProvider(
        string Name, string ClientId, string ClientSecret, string AuthorizeUrl, string TokenUrl, string RevokeUrl,
        string UserinfoUrl, string IdPath, string LoginPath, string Scopes, string TokenAuth,
        List<(string, string)> AuthorizeParams, List<(string, string)> ApiHeaders, bool EagerRefresh);

    public sealed record OauthConfig(
        string BaseUrl, List<string> AppUrls, long StateTtlSecs, long RefreshMarginSecs, List<OauthProvider> Providers)
    {
        public OauthProvider Provider(string name) =>
            Providers.FirstOrDefault(p => p.Name == name) ?? throw new Exception($"unknown provider `{name}`");
        public string RedirectUri => $"{BaseUrl}/route/oauth/callback";
        public bool Allowed(string url) => AppUrls.Any(p => url.StartsWith(p, StringComparison.Ordinal));
    }

    /// <summary>Built-in provider settings. Anything can be overridden in OAUTH_CONFIG.</summary>
    static JsonObject OauthPreset(string name) => name switch
    {
        "twitch" => new()
        {
            ["authorize_url"] = "https://id.twitch.tv/oauth2/authorize", ["token_url"] = "https://id.twitch.tv/oauth2/token",
            ["revoke_url"] = "https://id.twitch.tv/oauth2/revoke", ["userinfo_url"] = "https://api.twitch.tv/helix/users",
            ["id_path"] = "data.0.id", ["login_path"] = "data.0.login",
            ["api_headers"] = new JsonObject { ["Client-Id"] = "{client_id}" },
        },
        "discord" => new()
        {
            ["authorize_url"] = "https://discord.com/oauth2/authorize", ["token_url"] = "https://discord.com/api/oauth2/token",
            ["revoke_url"] = "https://discord.com/api/oauth2/token/revoke", ["userinfo_url"] = "https://discord.com/api/users/@me",
            ["id_path"] = "id", ["login_path"] = "username", ["scopes"] = "identify",
        },
        "google" => new()
        {
            ["authorize_url"] = "https://accounts.google.com/o/oauth2/v2/auth", ["token_url"] = "https://oauth2.googleapis.com/token",
            ["revoke_url"] = "https://oauth2.googleapis.com/revoke", ["userinfo_url"] = "https://openidconnect.googleapis.com/v1/userinfo",
            ["id_path"] = "sub", ["login_path"] = "email", ["scopes"] = "openid email profile",
            ["authorize_params"] = new JsonObject { ["access_type"] = "offline", ["prompt"] = "consent" },
        },
        "github" => new()
        {
            ["authorize_url"] = "https://github.com/login/oauth/authorize", ["token_url"] = "https://github.com/login/oauth/access_token",
            ["userinfo_url"] = "https://api.github.com/user", ["id_path"] = "id", ["login_path"] = "login", ["scopes"] = "read:user",
        },
        "spotify" => new()
        {
            ["authorize_url"] = "https://accounts.spotify.com/authorize", ["token_url"] = "https://accounts.spotify.com/api/token",
            ["userinfo_url"] = "https://api.spotify.com/v1/me", ["id_path"] = "id", ["login_path"] = "display_name",
            ["scopes"] = "user-read-private", ["token_auth"] = "basic",
        },
        _ => new() { ["id_path"] = "sub", ["login_path"] = "preferred_username" },
    };

    public static OauthConfig OauthParseConfig(string raw)
    {
        JsonNode? v;
        try { v = JsonNode.Parse(raw); }
        catch (Exception e) { throw new Exception($"OAUTH_CONFIG is not JSON: {e.Message}"); }
        var baseUrl = (OauthStr(v?["base_url"]) ?? throw new Exception("OAUTH_CONFIG.base_url is required")).TrimEnd('/');
        var appUrls = new List<string> { $"{baseUrl}/route/" };
        if (v?["app_urls"] is JsonArray urls) appUrls.AddRange(urls.Select(OauthStr).OfType<string>());
        var providers = new List<OauthProvider>();
        if (v?["providers"] is not JsonObject provs) throw new Exception("OAUTH_CONFIG.providers is required");
        foreach (var (name, node) in provs)
        {
            if (node is not JsonObject over) throw new Exception("provider config must be an object");
            var merged = OauthPreset(OauthStr(over["preset"]) ?? name);
            foreach (var (k, val) in over) merged[k] = val?.DeepClone();
            string S(string k) => OauthStr(merged[k]) ?? "";
            List<(string, string)> Pairs(string k) =>
                merged[k] is JsonObject o ? o.Select(kv => (kv.Key, OauthStr(kv.Value) ?? "")).ToList() : new();
            var p = new OauthProvider(
                name, S("client_id"), S("client_secret"), S("authorize_url"), S("token_url"), S("revoke_url"),
                S("userinfo_url"), S("id_path"), S("login_path"), S("scopes"), S("token_auth") == "basic" ? "basic" : "post",
                Pairs("authorize_params"), Pairs("api_headers"),
                merged["eager_refresh"] is JsonValue ev && ev.TryGetValue<bool>(out var eager) ? eager : true);
            foreach (var (field, val) in new[] { ("client_id", p.ClientId), ("authorize_url", p.AuthorizeUrl), ("token_url", p.TokenUrl), ("userinfo_url", p.UserinfoUrl) })
            {
                if (val.Length == 0) throw new Exception($"provider `{name}` is missing `{field}`");
            }
            providers.Add(p);
        }
        long Num(string k, long d) => v?[k] is JsonValue n && n.TryGetValue<long>(out var x) ? x : d;
        return new OauthConfig(baseUrl, appUrls, Num("state_ttl_secs", 600), Num("refresh_margin_secs", 300), providers);
    }

    static OauthConfig OauthCfg() => OauthParseConfig(OauthEnv.OAUTH_CONFIG);

    // -----------------------------------------------------------------------
    // Tables
    // -----------------------------------------------------------------------

    /// <summary>A link attempt in progress: single-use, short-lived, bound to its identity.</summary>
    [SpacetimeDB.Table(Accessor = "OauthState")]
    public partial struct OauthState
    {
        [SpacetimeDB.PrimaryKey]
        public string State;
        [SpacetimeDB.Index.BTree]
        public Identity Identity;
        public string Provider;
        public string Verifier;
        public string Scopes;
        public string ReturnTo;
        public Timestamp CreatedAt;
        public Timestamp ExpiresAt;
    }

    /// <summary>A linked account. Private: clients read their own through oauth_my_accounts.</summary>
    [SpacetimeDB.Table(Accessor = "OauthAccount")]
    [SpacetimeDB.Index.BTree(Accessor = "ByExternal", Columns = new[] { nameof(Provider), nameof(ExternalId) })]
    public partial struct OauthAccount
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public Identity Identity;
        public string Provider;
        public string ExternalId;
        public string Login;
        public string Scopes;
        public Timestamp LinkedAt;
        /// <summary>"ok", or "relink" when the provider stopped accepting the refresh token.</summary>
        public string Status;
        public string LastError;
    }

    /// <summary>The secrets. Private, never exposed by any view.</summary>
    [SpacetimeDB.Table(Accessor = "OauthToken")]
    public partial struct OauthToken
    {
        [SpacetimeDB.PrimaryKey]
        public ulong AccountId;
        public string AccessToken;
        public string? RefreshToken;
        public Timestamp? ExpiresAt;
        public Timestamp RefreshedAt;
        public Timestamp? RefreshingUntil;
        public uint RefreshFailures;
    }

    [SpacetimeDB.Table(Accessor = "OauthRefreshJob", Scheduled = nameof(OauthRefreshDue), ScheduledAt = nameof(OauthRefreshJob.ScheduledAt))]
    public partial struct OauthRefreshJob
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong ScheduledId;
        public ScheduleAt ScheduledAt;
        [SpacetimeDB.Index.BTree]
        public ulong AccountId;
    }

    static OauthAccountInfo OauthInfo(OauthAccount a, OauthToken? t) => new()
    {
        Provider = a.Provider, ExternalId = a.ExternalId, Login = a.Login, Scopes = a.Scopes,
        LinkedAt = a.LinkedAt, Status = a.Status, ExpiresAt = t?.ExpiresAt,
    };

    /// <summary>The caller's linked accounts. Never includes tokens.</summary>
    [SpacetimeDB.View(Accessor = "OauthMyAccounts", Public = true)]
    public static List<OauthAccountInfo> OauthMyAccounts(ViewContext ctx) =>
        ctx.Db.OauthAccount.Identity.Filter(ctx.Sender)
            .Select(a => OauthInfo(a, ctx.Db.OauthToken.AccountId.Find(a.Id)))
            .ToList();

    // -----------------------------------------------------------------------
    // Client procedures
    // -----------------------------------------------------------------------

    /// <summary>
    /// Start linking: returns the provider's authorize URL. scopes "" = the provider's defaults.
    /// returnTo "" = popup mode; otherwise the browser is redirected there with
    /// #oauth_state=..&amp;oauth_code=..
    /// </summary>
    [SpacetimeDB.Procedure]
    public static Result<string, string> OauthBegin(ProcedureContext ctx, string provider, string scopes, string returnTo)
    {
        try
        {
            var cfg = OauthCfg();
            var p = cfg.Provider(provider);
            scopes = string.IsNullOrWhiteSpace(scopes) ? p.Scopes : scopes.Trim();
            if (scopes.Any(c => char.IsControl(c) || c == '"')) throw new Exception("bad scopes");
            if (returnTo.Length > 0 && !cfg.Allowed(returnTo)) throw new Exception("return_to is not an allowed app URL");
            var who = ctx.Sender;
            var seed = $"{who}|{ctx.Timestamp.MicrosecondsSinceUnixEpoch}|{Interlocked.Increment(ref oauthNonce)}|{ctx.Rng.NextInt64()}";
            var secret = OauthEnv.OAUTH_SECRET;
            var state = OauthB64Url(OauthSha256.Hmac(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"state|{seed}")));
            var verifier = OauthB64Url(OauthSha256.Hmac(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"verifier|{seed}")));
            var challenge = OauthB64Url(OauthSha256.Hash(Encoding.ASCII.GetBytes(verifier)));
            var row = new OauthState
            {
                State = state, Identity = who, Provider = provider, Verifier = verifier, Scopes = scopes, ReturnTo = returnTo,
                CreatedAt = ctx.Timestamp, ExpiresAt = ctx.Timestamp + TimeDuration.FromSeconds(cfg.StateTtlSecs),
            };
            ctx.WithTx(tx =>
            {
                // Housekeeping: expired attempts, and all but the newest few for this identity.
                foreach (var s in tx.Db.OauthState.Iter().Where(s => s.ExpiresAt < tx.Timestamp).ToList()) tx.Db.OauthState.State.Delete(s.State);
                var mine = tx.Db.OauthState.Identity.Filter(who).OrderBy(s => s.CreatedAt.MicrosecondsSinceUnixEpoch).ToList();
                foreach (var s in mine.Take(Math.Max(0, mine.Count + 1 - OauthMaxPending))) tx.Db.OauthState.State.Delete(s.State);
                tx.Db.OauthState.Insert(row);
                return 0;
            });
            var q = new List<(string, string)>
            {
                ("response_type", "code"), ("client_id", p.ClientId), ("redirect_uri", cfg.RedirectUri), ("state", state),
                ("code_challenge", challenge), ("code_challenge_method", "S256"),
            };
            if (scopes.Length > 0) q.Add(("scope", scopes));
            var url = $"{p.AuthorizeUrl}{(p.AuthorizeUrl.Contains('?') ? "&" : "?")}{OauthForm(q)}";
            foreach (var (k, val) in p.AuthorizeParams) url += $"&{OauthEnc(k)}={OauthEnc(val)}";
            return Result<string, string>.Ok(url);
        }
        catch (Exception e)
        {
            return Result<string, string>.Err(e.Message);
        }
    }

    /// <summary>
    /// Finish linking with the state and code from the callback. Only the identity that began can
    /// finish. Returns the linked login; oauth_my_accounts has the details. (Every procedure here
    /// returns Result&lt;string, string&gt;: the TypeScript submodule can't return a Result whose two
    /// sides differ in 2.11, and all three languages share one schema.)
    /// </summary>
    [SpacetimeDB.Procedure]
    public static Result<string, string> OauthComplete(ProcedureContext ctx, string state, string code)
    {
        try { return Result<string, string>.Ok(OauthCompleteInner(ctx, state, code).Login); }
        catch (Exception e) { return Result<string, string>.Err(e.Message); }
    }

    static OauthAccountInfo OauthCompleteInner(ProcedureContext ctx, string state, string code)
    {
        var cfg = OauthCfg();
        var who = ctx.Sender;
        var (pending, error) = ctx.WithTx(tx =>
        {
            if (tx.Db.OauthState.State.Find(state) is not { } s) return ((OauthState?)null, "unknown or already used state");
            if (s.Identity != who) return (null, "this link attempt belongs to another identity");
            tx.Db.OauthState.State.Delete(state);
            if (s.ExpiresAt < tx.Timestamp) return (null, "link attempt expired, start again");
            return (s, "");
        });
        if (pending is not { } ps) throw new Exception(error);
        var p = cfg.Provider(ps.Provider);
        var tokens = OauthTokenRequest(ctx, p, new()
        {
            ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", cfg.RedirectUri), ("code_verifier", ps.Verifier),
        }, out var tokenError);
        if (tokens is null) throw new Exception(tokenError.Message);
        var access = OauthStr(tokens["access_token"])!;
        string externalId, login;
        try { (externalId, login) = OauthUserinfo(ctx, p, access); }
        catch { OauthRevoke(ctx, p, access); throw; }
        var scopes = OauthScopesOf(tokens) ?? ps.Scopes;
        var expiresAt = OauthExpiresAt(tokens, ctx.Timestamp);
        var refreshToken = OauthStr(tokens["refresh_token"]);
        var (info, linkError) = ctx.WithTx(tx =>
        {
            if (tx.Db.OauthAccount.ByExternal.Filter((p.Name, externalId)).Any(a => a.Identity != who))
            {
                return ((OauthAccountInfo?)null, $"that {p.Name} account is already linked to another identity");
            }
            // One account per provider per identity: re-linking replaces the old one.
            if (OauthFindAccount(tx, who, p.Name) is { } old) OauthDeleteAccount(tx, old.Id);
            var a = tx.Db.OauthAccount.Insert(new OauthAccount
            {
                Id = 0, Identity = who, Provider = p.Name, ExternalId = externalId, Login = login, Scopes = scopes,
                LinkedAt = tx.Timestamp, Status = "ok", LastError = "",
            });
            var t = tx.Db.OauthToken.Insert(new OauthToken
            {
                AccountId = a.Id, AccessToken = access, RefreshToken = refreshToken, ExpiresAt = expiresAt, RefreshedAt = tx.Timestamp,
            });
            if (p.EagerRefresh) OauthScheduleRefresh(tx, t, cfg.RefreshMarginSecs);
            return (OauthInfo(a, t), "");
        });
        if (info is { } ok) return ok;
        OauthRevoke(ctx, p, access);
        throw new Exception(linkError);
    }

    /// <summary>Unlink the caller's account for provider, revoking its tokens (best effort). Returns the provider's name.</summary>
    [SpacetimeDB.Procedure]
    public static Result<string, string> OauthUnlink(ProcedureContext ctx, string provider)
    {
        try { OauthUnlinkAccount(ctx, ctx.Sender, provider); return Result<string, string>.Ok(provider); }
        catch (Exception e) { return Result<string, string>.Err(e.Message); }
    }

    // -----------------------------------------------------------------------
    // Library API: call these from your own procedures
    // -----------------------------------------------------------------------

    /// <summary>
    /// Run call with a valid access token for who's provider account. Refreshes first if the token
    /// is about to expire, and once more (then retries) if call gets a 401.
    /// </summary>
    public static HttpResponse OauthWithToken(ProcedureContext ctx, Identity who, string provider, Func<string, HttpResponse> call)
    {
        var (accountId, access, expiresAt, canRefresh, error) = ctx.WithTx(tx =>
        {
            if (OauthFindAccount(tx, who, provider) is not { } a) return (0UL, "", (Timestamp?)null, false, $"no linked {provider} account");
            if (a.Status != "ok") return (0UL, "", null, false, $"the {provider} account needs to be linked again");
            if (tx.Db.OauthToken.AccountId.Find(a.Id) is not { } t) return (0UL, "", null, false, "no token");
            return (a.Id, t.AccessToken, t.ExpiresAt, t.RefreshToken is not null, "");
        });
        if (error.Length > 0) throw new Exception(error);
        if (canRefresh && expiresAt is { } e && e < ctx.Timestamp + TimeDuration.FromSeconds(30)) access = OauthRefresh(ctx, accountId);
        var response = call(access);
        if (response.StatusCode != 401 || !canRefresh) return response;
        access = OauthRefresh(ctx, accountId);
        return call(access);
    }

    /// <summary>GET url as who's provider account (bearer token plus the provider's API headers).</summary>
    public static (ushort Status, string Body) OauthGet(ProcedureContext ctx, Identity who, string provider, string url)
    {
        var p = OauthCfg().Provider(provider);
        var response = OauthWithToken(ctx, who, provider, token =>
            ctx.Http.Send(OauthApiRequest(p, url, token)).Match(r => r, e => throw new Exception(e.Message)));
        return (response.StatusCode, response.Body.ToStringUtf8Lossy());
    }

    /// <summary>Unlink who's provider account and revoke its tokens (best effort).</summary>
    public static void OauthUnlinkAccount(ProcedureContext ctx, Identity who, string provider)
    {
        var (token, error) = ctx.WithTx(tx =>
        {
            if (OauthFindAccount(tx, who, provider) is not { } a) return ((OauthToken?)null, $"no linked {provider} account");
            var t = tx.Db.OauthToken.AccountId.Find(a.Id);
            OauthDeleteAccount(tx, a.Id);
            return (t, "");
        });
        if (error.Length > 0) throw new Exception(error);
        if (token is { } t && OauthCfg().Providers.FirstOrDefault(x => x.Name == provider) is { } p)
        {
            OauthRevoke(ctx, p, t.RefreshToken ?? t.AccessToken);
        }
    }

    /// <summary>Who's linked account at provider, if any. Works in reducers too.</summary>
    public static OauthAccount? OauthLinkedAccount(Local db, Identity who, string provider) =>
        db.OauthAccount.Identity.Filter(who).Where(a => a.Provider == provider).Select(a => (OauthAccount?)a).FirstOrDefault();

    /// <summary>Add the callback route to your [HttpRouter].</summary>
    public static Router OauthRoutes(Router router) => router.Get("/oauth/callback", Handlers.OauthCallback);

    // -----------------------------------------------------------------------
    // Callback and refresh
    // -----------------------------------------------------------------------

    /// <summary>
    /// The provider redirects the browser here. No tokens are handled: the page hands state and
    /// code to the app (popup opener, or returnTo), which calls oauth_complete.
    /// </summary>
    [SpacetimeDB.HttpHandler]
    public static HttpResponse OauthCallback(HandlerContext ctx, HttpRequest req)
    {
        var qi = req.Uri.IndexOf('?');
        var q = OauthParseQuery(qi < 0 ? "" : req.Uri[(qi + 1)..]);
        string Get(string k) => q.FirstOrDefault(x => x.Item1 == k).Item2 ?? "";
        var (state, code, error) = (Get("state"), Get("code"), Get("error"));
        OauthConfig cfg;
        try { cfg = OauthParseConfig(ctx.WithTx(_ => OauthEnv.OAUTH_CONFIG)); }
        catch (Exception e) { return OauthHtml(500, OauthResultPage(new JsonObject { ["error"] = e.Message }, new())); }
        var pending = ctx.WithTx(tx =>
        {
            var s = tx.Db.OauthState.State.Find(state);
            // A provider-side error (e.g. the user clicked Deny) ends this attempt.
            if (s is not null && error.Length > 0) tx.Db.OauthState.State.Delete(state);
            return s;
        });
        var msg = new JsonObject { ["type"] = "spacetimedb-oauth", ["state"] = state };
        if (pending is { } ps0) msg["provider"] = ps0.Provider;
        if (error.Length > 0)
        {
            var desc = Get("error_description");
            msg["error"] = desc.Length == 0 ? error : $"{error}: {desc}";
        }
        else if (pending is null) msg["error"] = "unknown or expired link attempt";
        else msg["code"] = code;
        // Redirect mode: hand the result to the app in the URL fragment (never sent to servers).
        if (pending is { ReturnTo.Length: > 0 } ps)
        {
            var frag = new List<(string, string)>();
            foreach (var (k, val) in msg)
            {
                if (k == "type") continue;
                var name = k switch { "state" => "oauth_state", "code" => "oauth_code", "error" => "oauth_error", _ => "oauth_provider" };
                frag.Add((name, OauthStr(val) ?? ""));
            }
            return new(302, HttpVersion.Http11,
                new List<HttpHeader> { new("location", $"{ps.ReturnTo}#{OauthForm(frag)}"), new("cache-control", "no-store") },
                HttpBody.Empty);
        }
        return OauthHtml(200, OauthResultPage(msg, cfg.AppUrls));
    }

    /// <summary>Scheduled: refresh a token ahead of its expiry.</summary>
    [SpacetimeDB.Procedure]
    public static void OauthRefreshDue(ProcedureContext ctx, OauthRefreshJob job)
    {
        try { OauthRefresh(ctx, job.AccountId); }
        catch (Exception e) { Log.Info($"oauth: scheduled refresh of account {job.AccountId}: {e.Message}"); }
    }

    /// <summary>Refresh accountId's token now. Returns the new access token.</summary>
    static string OauthRefresh(ProcedureContext ctx, ulong accountId)
    {
        var cfg = OauthCfg();
        var lease = ctx.Timestamp + new TimeDuration(OauthLeaseUs);
        var (provider, refreshToken, claimError) = ctx.WithTx(tx =>
        {
            if (tx.Db.OauthAccount.Id.Find(accountId) is not { } a) return ("", "", "account is gone");
            if (tx.Db.OauthToken.AccountId.Find(accountId) is not { } t) return ("", "", "token is gone");
            if (t.RefreshToken is null) return ("", "", "no refresh token");
            if (t.RefreshingUntil is { } u && u > tx.Timestamp) return ("", "", "a refresh is already in progress, try again shortly");
            tx.Db.OauthToken.AccountId.Update(t with { RefreshingUntil = lease });
            return (a.Provider, t.RefreshToken, "");
        });
        if (claimError.Length > 0) throw new Exception(claimError);
        var p = cfg.Provider(provider);
        var tokens = OauthTokenRequest(ctx, p, new() { ("grant_type", "refresh_token"), ("refresh_token", refreshToken) }, out var err);
        var (access, error) = ctx.WithTx(tx =>
        {
            if (tx.Db.OauthAccount.Id.Find(accountId) is not { } a) return ("", "account is gone");
            if (tx.Db.OauthToken.AccountId.Find(accountId) is not { } t) return ("", "token is gone");
            t.RefreshingUntil = null;
            OauthClearJobs(tx, accountId);
            if (tokens is not null)
            {
                if (OauthStr(tokens["access_token"]) is not { } at) return ("", "no access_token in refresh response");
                t.AccessToken = at;
                if (OauthStr(tokens["refresh_token"]) is { } rt) t.RefreshToken = rt;
                t.ExpiresAt = OauthExpiresAt(tokens, tx.Timestamp);
                t.RefreshedAt = tx.Timestamp;
                t.RefreshFailures = 0;
                if (OauthScopesOf(tokens) is { } scopes) tx.Db.OauthAccount.Id.Update(a with { Scopes = scopes });
                tx.Db.OauthToken.AccountId.Update(t);
                if (p.EagerRefresh) OauthScheduleRefresh(tx, t, cfg.RefreshMarginSecs);
                return (at, "");
            }
            if (err.Permanent)
            {
                // The grant is gone (revoked, expired): the user has to link again.
                tx.Db.OauthToken.AccountId.Delete(accountId);
                tx.Db.OauthAccount.Id.Update(a with { Status = "relink", LastError = err.Message });
                return ("", err.Message);
            }
            t.RefreshFailures++;
            tx.Db.OauthAccount.Id.Update(a with { LastError = err.Message });
            tx.Db.OauthToken.AccountId.Update(t);
            if (t.RefreshFailures <= OauthMaxRefreshFailures)
            {
                var backoff = TimeDuration.FromSeconds(15L << (int)Math.Min(t.RefreshFailures, 8));
                tx.Db.OauthRefreshJob.Insert(new OauthRefreshJob { ScheduledId = 0, ScheduledAt = tx.Timestamp + backoff, AccountId = accountId });
            }
            return ("", err.Message);
        });
        if (error.Length > 0) throw new Exception(error);
        return access;
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    readonly record struct OauthTokenError(string Message, bool Permanent);

    static JsonNode? OauthTokenRequest(ProcedureContext ctx, OauthProvider p, List<(string, string)> form, out OauthTokenError error)
    {
        var headers = new List<HttpHeader> { new("content-type", "application/x-www-form-urlencoded"), new("accept", "application/json") };
        if (p.TokenAuth == "basic")
        {
            var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{OauthEnc(p.ClientId)}:{OauthEnc(p.ClientSecret)}"));
            headers.Add(new("authorization", $"Basic {creds}"));
        }
        else
        {
            form.Add(("client_id", p.ClientId));
            form.Add(("client_secret", p.ClientSecret));
        }
        var request = new HttpRequest
        {
            Uri = p.TokenUrl, Method = HttpMethod.Post, Timeout = OauthHttpTimeout, Headers = headers,
            Body = HttpBody.FromString(OauthForm(form)),
        };
        var (result, err) = ctx.Http.Send(request).Match<(JsonNode?, OauthTokenError)>(
            response =>
            {
                var text = response.Body.ToStringUtf8Lossy();
                JsonNode? body = null;
                try { body = JsonNode.Parse(text); } catch { }
                if (response.StatusCode is >= 200 and < 300 && OauthStr(body?["access_token"]) is not null) return (body, default);
                var code = OauthStr(body?["error"]) ?? "";
                var desc = OauthStr(body?["error_description"]) ?? "";
                var status = response.StatusCode;
                var message = code.Length == 0 ? $"token endpoint: {status} {(text.Length > 200 ? text[..200] : text)}" : $"{code}: {desc}";
                var permanent = code == "invalid_grant" || (status is >= 400 and < 500 && status is not (408 or 429));
                return (null, new OauthTokenError(message, permanent));
            },
            e => (null, new OauthTokenError($"token endpoint: {e.Message}", false)));
        error = err;
        return result;
    }

    static HttpRequest OauthApiRequest(OauthProvider p, string url, string token)
    {
        var headers = new List<HttpHeader>
        {
            new("authorization", $"Bearer {token}"), new("accept", "application/json"), new("user-agent", "spacetimedb-oauth"),
        };
        foreach (var (k, v) in p.ApiHeaders) headers.Add(new(k, v.Replace("{client_id}", p.ClientId)));
        return new HttpRequest { Uri = url, Method = HttpMethod.Get, Timeout = OauthHttpTimeout, Headers = headers };
    }

    static (string Id, string Login) OauthUserinfo(ProcedureContext ctx, OauthProvider p, string token)
    {
        var response = ctx.Http.Send(OauthApiRequest(p, p.UserinfoUrl, token)).Match(r => r, e => throw new Exception($"userinfo: {e.Message}"));
        var text = response.Body.ToStringUtf8Lossy();
        if (response.StatusCode is < 200 or >= 300) throw new Exception($"userinfo: {response.StatusCode} {(text.Length > 200 ? text[..200] : text)}");
        JsonNode? v;
        try { v = JsonNode.Parse(text); }
        catch (Exception e) { throw new Exception($"userinfo is not JSON: {e.Message}"); }
        var id = OauthAtPath(v, p.IdPath) ?? throw new Exception($"userinfo has no `{p.IdPath}`");
        return (id, OauthAtPath(v, p.LoginPath) ?? "");
    }

    /// <summary>Revoke a token at the provider, if it supports revocation. Best effort.</summary>
    static void OauthRevoke(ProcedureContext ctx, OauthProvider p, string token)
    {
        if (p.RevokeUrl.Length == 0) return;
        var form = new List<(string, string)> { ("token", token) };
        var headers = new List<HttpHeader> { new("content-type", "application/x-www-form-urlencoded") };
        if (p.TokenAuth == "basic")
        {
            headers.Add(new("authorization", $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{OauthEnc(p.ClientId)}:{OauthEnc(p.ClientSecret)}"))}"));
        }
        else
        {
            form.Add(("client_id", p.ClientId));
            form.Add(("client_secret", p.ClientSecret));
        }
        ctx.Http.Send(new HttpRequest
        {
            Uri = p.RevokeUrl, Method = HttpMethod.Post, Timeout = OauthHttpTimeout, Headers = headers, Body = HttpBody.FromString(OauthForm(form)),
        }).Match(_ => 0, e => { Log.Info($"oauth: revoke at {p.Name}: {e.Message}"); return 0; });
    }

    static OauthAccount? OauthFindAccount(ProcedureTxContext tx, Identity who, string provider) =>
        OauthLinkedAccount(tx.Db, who, provider);

    static void OauthDeleteAccount(ProcedureTxContext tx, ulong accountId)
    {
        OauthClearJobs(tx, accountId);
        tx.Db.OauthToken.AccountId.Delete(accountId);
        tx.Db.OauthAccount.Id.Delete(accountId);
    }

    static void OauthClearJobs(ProcedureTxContext tx, ulong accountId)
    {
        foreach (var j in tx.Db.OauthRefreshJob.AccountId.Filter(accountId).ToList()) tx.Db.OauthRefreshJob.ScheduledId.Delete(j.ScheduledId);
    }

    /// <summary>Refresh margin before expiry (at most a fifth of the token's lifetime early).</summary>
    static void OauthScheduleRefresh(ProcedureTxContext tx, OauthToken t, long marginSecs)
    {
        if (t.ExpiresAt is not { } exp || t.RefreshToken is null) return;
        var now = tx.Timestamp.MicrosecondsSinceUnixEpoch;
        var life = exp.MicrosecondsSinceUnixEpoch - now;
        var early = Math.Max(0, Math.Min(marginSecs * 1_000_000, life / 5));
        var at = new Timestamp(Math.Max(exp.MicrosecondsSinceUnixEpoch - early, now));
        tx.Db.OauthRefreshJob.Insert(new OauthRefreshJob { ScheduledId = 0, ScheduledAt = at, AccountId = t.AccountId });
    }

    static Timestamp? OauthExpiresAt(JsonNode tokens, Timestamp now)
    {
        double secs;
        if (tokens["expires_in"] is JsonValue v && v.TryGetValue<double>(out var d)) secs = d;
        else if (OauthStr(tokens["expires_in"]) is { } s && double.TryParse(s, out var ds)) secs = ds;
        else return null;
        return secs > 0 ? now + TimeDuration.FromSeconds(secs) : null;
    }

    /// <summary>Granted scopes, space-separated (Twitch returns an array).</summary>
    static string? OauthScopesOf(JsonNode tokens) => tokens["scope"] switch
    {
        JsonArray a => string.Join(" ", a.Select(OauthStr).OfType<string>()),
        JsonValue v when v.TryGetValue<string>(out var s) => s.Replace(',', ' '),
        _ => null,
    };

    /// <summary>"data.0.id" style lookup; numbers come back as strings.</summary>
    static string? OauthAtPath(JsonNode? v, string path)
    {
        foreach (var part in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            v = v switch
            {
                JsonArray a when int.TryParse(part, out var i) => i < a.Count ? a[i] : null,
                JsonObject o => o[part],
                _ => null,
            };
            if (v is null) return null;
        }
        return OauthStr(v);
    }

    static string? OauthStr(JsonNode? n)
    {
        if (n is not JsonValue v) return null;
        if (v.TryGetValue<string>(out var s)) return s;
        if (v.TryGetValue<long>(out var l)) return l.ToString();
        if (v.TryGetValue<double>(out var d)) return d.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (v.TryGetValue<bool>(out var b)) return b ? "true" : "false";
        return null;
    }

    static string OauthB64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Percent-encode everything but RFC 3986 unreserved characters.</summary>
    static string OauthEnc(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if (b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~') sb.Append((char)b);
            else sb.Append('%').Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    static string OauthForm(List<(string, string)> pairs) => string.Join("&", pairs.Select(p => $"{OauthEnc(p.Item1)}={OauthEnc(p.Item2)}"));

    static List<(string, string)> OauthParseQuery(string q)
    {
        static string Dec(string s)
        {
            var b = Encoding.UTF8.GetBytes(s.Replace('+', ' '));
            var outp = new List<byte>(b.Length);
            for (var i = 0; i < b.Length; i++)
            {
                if (b[i] == '%' && i + 2 < b.Length && byte.TryParse(Encoding.ASCII.GetString(b, i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out var h))
                {
                    outp.Add(h);
                    i += 2;
                }
                else outp.Add(b[i]);
            }
            return Encoding.UTF8.GetString(outp.ToArray());
        }
        return q.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.IndexOf('=') is var i and >= 0 ? (Dec(p[..i]), Dec(p[(i + 1)..])) : (Dec(p), ""))
            .ToList();
    }

    static HttpResponse OauthHtml(ushort status, string body) =>
        new(status, HttpVersion.Http11,
            new List<HttpHeader> { new("content-type", "text/html; charset=utf-8"), new("cache-control", "no-store"), new("referrer-policy", "no-referrer") },
            HttpBody.FromString(body));

    /// <summary>
    /// The page the provider redirects to. It hands the result to the window that opened it, but
    /// only if that window is an allowed app URL (same-origin openers are checked by full URL
    /// prefix, so another app on a shared host can't receive it).
    /// </summary>
    static string OauthResultPage(JsonObject msg, List<string> allowed)
    {
        var arr = new JsonArray();
        foreach (var a in allowed) arr.Add((JsonNode?)JsonValue.Create(a));
        return OauthResultHtml
            .Replace("/*MSG*/null", msg.ToJsonString().Replace("<", "\\u003c"))
            .Replace("/*ALLOWED*/[]", arr.ToJsonString().Replace("<", "\\u003c"));
    }

    const string OauthResultHtml = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linking account</title>
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
</script></body></html>
""";
}

/// <summary>Small managed SHA-256 / HMAC-SHA256 (System.Security.Cryptography isn't available on wasi).</summary>
static class OauthSha256
{
    static readonly uint[] K =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    static uint Rotr(uint x, int n) => (x >> n) | (x << (32 - n));

    public static byte[] Hash(byte[] data)
    {
        uint[] h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        var bitLen = (ulong)data.LongLength * 8;
        var padded = new byte[((data.Length + 9 + 63) / 64) * 64];
        data.CopyTo(padded, 0);
        padded[data.Length] = 0x80;
        for (var i = 0; i < 8; i++) padded[padded.Length - 1 - i] = (byte)(bitLen >> (8 * i));
        var w = new uint[64];
        for (var chunk = 0; chunk < padded.Length; chunk += 64)
        {
            for (var i = 0; i < 16; i++)
                w[i] = (uint)(padded[chunk + 4 * i] << 24 | padded[chunk + 4 * i + 1] << 16 | padded[chunk + 4 * i + 2] << 8 | padded[chunk + 4 * i + 3]);
            for (var i = 16; i < 64; i++)
            {
                var s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                var s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (var i = 0; i < 64; i++)
            {
                var t1 = hh + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
                var t2 = (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }
        var result = new byte[32];
        for (var i = 0; i < 8; i++)
        {
            result[4 * i] = (byte)(h[i] >> 24); result[4 * i + 1] = (byte)(h[i] >> 16);
            result[4 * i + 2] = (byte)(h[i] >> 8); result[4 * i + 3] = (byte)h[i];
        }
        return result;
    }

    public static byte[] Hmac(byte[] key, byte[] message)
    {
        if (key.Length > 64) key = Hash(key);
        var k = new byte[64];
        key.CopyTo(k, 0);
        var inner = new byte[64 + message.Length];
        var outer = new byte[64 + 32];
        for (var i = 0; i < 64; i++) { inner[i] = (byte)(k[i] ^ 0x36); outer[i] = (byte)(k[i] ^ 0x5c); }
        message.CopyTo(inner, 64);
        Hash(inner).CopyTo(outer, 64);
        return Hash(outer);
    }
}
