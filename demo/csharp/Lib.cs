// Demo: link an account at a (mock) OAuth provider, see it, call its API, unlink it.
// Serves the web client at /route/. The C# twin of demo/rust.

#pragma warning disable STDB_UNSTABLE

using SpacetimeDB;

public static partial class Module
{
    /// <summary>
    /// Call the provider's API as the caller (the mock's /api/me, or the provider's userinfo).
    /// Shows OauthGet refreshing and retrying behind the scenes.
    /// </summary>
    [SpacetimeDB.Procedure]
    public static Result<string, string> DemoProfile(ProcedureContext ctx, string provider, string url)
    {
        try
        {
            var (status, body) = OauthGet(ctx, ctx.Sender, provider, url);
            return status >= 400 ? Result<string, string>.Err($"{status}: {body}") : Result<string, string>.Ok(body);
        }
        catch (Exception e)
        {
            return Result<string, string>.Err(e.Message);
        }
    }

    static readonly Lazy<byte[]> DemoPage = new(() =>
    {
        using var s = typeof(Module).Assembly.GetManifestResourceStream("index.html")!;
        using var m = new MemoryStream();
        s.CopyTo(m);
        return m.ToArray();
    });

    [SpacetimeDB.HttpHandler]
    public static HttpResponse Page(HandlerContext ctx, HttpRequest req) =>
        new(200, HttpVersion.Http11,
            new List<HttpHeader> { new("content-type", "text/html; charset=utf-8"), new("cache-control", "no-cache") },
            new HttpBody(DemoPage.Value));

    [SpacetimeDB.HttpRouter]
    public static Router Routes() => OauthRoutes(Router.New()).Get("/", Handlers.Page);
}
