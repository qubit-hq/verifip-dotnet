namespace VerifIP.Models;

/// <summary>
/// Rate limit information parsed from API response headers.
/// </summary>
public sealed class RateLimitInfo
{
    public int Limit { get; }
    public int Remaining { get; }
    public DateTimeOffset Reset { get; }

    public RateLimitInfo(int limit, int remaining, DateTimeOffset reset)
    {
        Limit = limit;
        Remaining = remaining;
        Reset = reset;
    }

    internal static RateLimitInfo? FromHeaders(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("X-RateLimit-Limit", out var limitValues))
            return null;

        var limitStr = limitValues.FirstOrDefault();
        if (limitStr == null || !int.TryParse(limitStr, out var limit))
            return null;

        int remaining = 0;
        if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var remValues))
        {
            int.TryParse(remValues.FirstOrDefault(), out remaining);
        }

        var reset = DateTimeOffset.UtcNow;
        if (response.Headers.TryGetValues("X-RateLimit-Reset", out var resetValues)
            && long.TryParse(resetValues.FirstOrDefault(), out var epoch))
        {
            reset = DateTimeOffset.FromUnixTimeSeconds(epoch);
        }

        return new RateLimitInfo(limit, remaining, reset);
    }
}
