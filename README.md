# VerifIP .NET SDK

Official .NET SDK for the [VerifIP](https://verifip.com) IP fraud risk scoring API.

## Installation

```bash
dotnet add package VerifIP
```

Or via NuGet Package Manager:
```
Install-Package VerifIP
```

## Quick Start

```csharp
using VerifIP;

var client = new VerifIPClient("vip_your_api_key");
var result = await client.CheckAsync("185.220.101.1");

Console.WriteLine(result.FraudScore);       // 70
Console.WriteLine(result.IsTor);            // true
Console.WriteLine(result.SignalBreakdown);  // {"tor_exit": 25, ...}
```

## Methods

### `CheckAsync(ip, cancellationToken)`

Check a single IPv4 or IPv6 address.

```csharp
var result = await client.CheckAsync("185.220.101.1");

result.RequestId       // UUID
result.Ip              // "185.220.101.1"
result.FraudScore      // 0-100
result.IsProxy         // bool
result.IsVpn           // bool
result.IsTor           // bool
result.IsDatacenter    // bool
result.CountryCode     // "DE"
result.CountryName     // "Germany"
result.Region          // "Brandenburg"
result.City            // "Brandenburg"
result.Isp             // "Stiftung Erneuerbare Freiheit"
result.Asn             // 60729
result.ConnectionType  // "Data Center"
result.Hostname        // "tor-exit.example.org"
result.SignalBreakdown // Dictionary<string, int>
```

### `CheckBatchAsync(ips, cancellationToken)`

Check up to 100 IPs. Requires Starter plan or higher.

```csharp
var batch = await client.CheckBatchAsync(new[] { "185.220.101.1", "8.8.8.8" });
foreach (var result in batch.Results)
    Console.WriteLine($"{result.Ip}: {result.FraudScore}");
```

### `HealthAsync(cancellationToken)`

Check API server health (no authentication required).

```csharp
var health = await client.HealthAsync();
Console.WriteLine(health.Status); // "ok"
```

## Error Handling

```csharp
using VerifIP.Exceptions;

try
{
    var result = await client.CheckAsync("1.2.3.4");
}
catch (AuthenticationException)
{
    // 401/403: invalid or disabled API key
}
catch (RateLimitException ex)
{
    // 429: daily limit exceeded
    Console.WriteLine($"Retry after {ex.RetryAfter} seconds");
}
catch (InvalidRequestException)
{
    // 400: malformed or private IP
}
catch (VerifIPException ex)
{
    // Catch-all for any API error
    Console.WriteLine($"Error {ex.StatusCode}: {ex.ErrorCode}");
}
```

## Rate Limits

```csharp
await client.CheckAsync("8.8.8.8");
if (client.RateLimit != null)
{
    Console.WriteLine($"{client.RateLimit.Remaining}/{client.RateLimit.Limit} requests left");
    Console.WriteLine($"Resets at {client.RateLimit.Reset}");
}
```

## Configuration

```csharp
var client = new VerifIPClient("vip_your_key", new VerifIPClientOptions
{
    BaseUrl = "https://api.verifip.com",    // default
    Timeout = TimeSpan.FromSeconds(30),     // default
    MaxRetries = 3,                          // default
    HttpClient = myCustomHttpClient          // optional
});
```

| Option | Default | Description |
|--------|---------|-------------|
| `BaseUrl` | `https://api.verifip.com` | API base URL |
| `Timeout` | 30 seconds | Request timeout |
| `MaxRetries` | 3 | Retries on 429/5xx with exponential backoff |
| `HttpClient` | null | Custom HttpClient (overrides BaseUrl/Timeout) |

## Retry Behavior

Automatic retry on HTTP 429 and 5xx with exponential backoff:
- Delay: `min(retry_after or 0.5 * 2^attempt, 30) + jitter`
- Respects `retry_after` from rate limit responses
- Connection errors are also retried
- Supports `CancellationToken` for cancellation

## Requirements

- .NET 6.0 or .NET 8.0
- Zero external dependencies (uses `System.Net.Http` and `System.Text.Json`)
- Implements `IDisposable` for proper HttpClient cleanup

## Links

- [API Documentation](https://verifip.com/docs)
- [GitHub](https://github.com/qubit-hq/verifip-dotnet)
- [NuGet](https://www.nuget.org/packages/VerifIP)
- [Changelog](https://github.com/qubit-hq/verifip-dotnet/releases)
