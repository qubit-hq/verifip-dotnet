using VerifIP;
using VerifIP.Exceptions;

// Read API key from environment variable
var apiKey = Environment.GetEnvironmentVariable("VERIFIP_API_KEY")
    ?? throw new Exception("Set VERIFIP_API_KEY environment variable");

using var client = new VerifIPClient(apiKey, new VerifIPClientOptions
{
    BaseUrl = "http://localhost:8080"
});

try
{
    // Single IP check
    var result = await client.CheckAsync("185.220.101.1");
    Console.WriteLine($"IP:          {result.Ip}");
    Console.WriteLine($"Fraud Score: {result.FraudScore}/100");
    Console.WriteLine($"Tor:         {result.IsTor}");
    Console.WriteLine($"VPN:         {result.IsVpn}");
    Console.WriteLine($"Country:     {result.CountryName} ({result.CountryCode})");
    Console.WriteLine($"ISP:         {result.Isp} (AS{result.Asn})");

    // Rate limit info
    if (client.RateLimit != null)
        Console.WriteLine($"Remaining:   {client.RateLimit.Remaining}/{client.RateLimit.Limit}");

    // Batch check
    var batch = await client.CheckBatchAsync(new[] { "8.8.8.8", "1.1.1.1" });
    foreach (var r in batch.Results)
        Console.WriteLine($"  {r.Ip}: score={r.FraudScore}");
}
catch (AuthenticationException)
{
    Console.WriteLine("Invalid API key");
}
catch (RateLimitException ex)
{
    Console.WriteLine($"Rate limited. Retry after {ex.RetryAfter} seconds.");
}
catch (VerifIPException ex)
{
    Console.WriteLine($"API error ({ex.StatusCode}): {ex.Message}");
}
