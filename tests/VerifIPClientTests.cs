using System.Net;
using System.Text.Json;
using VerifIP;
using VerifIP.Exceptions;
using VerifIP.Models;
using Xunit;

namespace VerifIP.Tests;

public class VerifIPClientTests
{
    private static VerifIPClient CreateClient(HttpClient httpClient)
    {
        return new VerifIPClient("vip_testkey", new VerifIPClientOptions
        {
            HttpClient = httpClient
        });
    }

    private static HttpClient MockHttp(HttpStatusCode status, object body, Dictionary<string, string>? headers = null)
    {
        var handler = new MockHandler(status, JsonSerializer.Serialize(body), headers);
        return new HttpClient(handler) { BaseAddress = new Uri("http://localhost:8080") };
    }

    [Fact]
    public async Task CheckAsync_ReturnsCheckResponse()
    {
        var mockResponse = new
        {
            request_id = "test-uuid",
            ip = "185.220.101.1",
            fraud_score = 70,
            is_proxy = true,
            is_vpn = true,
            is_tor = true,
            is_datacenter = true,
            country_code = "DE",
            country_name = "Germany",
            region = "Brandenburg",
            city = "Brandenburg",
            isp = "Stiftung Erneuerbare Freiheit",
            asn = 60729u,
            connection_type = "Data Center",
            hostname = "tor-exit.example.org",
            signal_breakdown = new Dictionary<string, int> { { "tor_exit", 25 }, { "datacenter_ip", 10 } }
        };

        var rateLimitHeaders = new Dictionary<string, string>
        {
            { "X-RateLimit-Limit", "1000" },
            { "X-RateLimit-Remaining", "999" },
            { "X-RateLimit-Reset", "1713052800" }
        };

        using var client = CreateClient(MockHttp(HttpStatusCode.OK, mockResponse, rateLimitHeaders));
        var result = await client.CheckAsync("185.220.101.1");

        Assert.Equal("test-uuid", result.RequestId);
        Assert.Equal(70, result.FraudScore);
        Assert.True(result.IsTor);
        Assert.True(result.IsVpn);
        Assert.Equal("DE", result.CountryCode);
        Assert.Equal(60729u, result.Asn);
        Assert.NotNull(result.SignalBreakdown);
        Assert.Equal(25, result.SignalBreakdown!["tor_exit"]);
    }

    [Fact]
    public async Task CheckAsync_ParsesRateLimit()
    {
        var headers = new Dictionary<string, string>
        {
            { "X-RateLimit-Limit", "1000" },
            { "X-RateLimit-Remaining", "847" },
            { "X-RateLimit-Reset", "1713052800" }
        };

        using var client = CreateClient(MockHttp(HttpStatusCode.OK, new { ip = "8.8.8.8", fraud_score = 0 }, headers));
        await client.CheckAsync("8.8.8.8");

        Assert.NotNull(client.RateLimit);
        Assert.Equal(1000, client.RateLimit!.Limit);
        Assert.Equal(847, client.RateLimit.Remaining);
    }

    [Fact]
    public async Task CheckAsync_EmptyIp_ThrowsArgumentException()
    {
        using var client = new VerifIPClient("vip_testkey");
        await Assert.ThrowsAsync<ArgumentException>(() => client.CheckAsync(""));
    }

    [Fact]
    public async Task CheckAsync_400_ThrowsInvalidRequestException()
    {
        var error = new { error = "invalid_ip", message = "Invalid IP address" };
        using var client = CreateClient(MockHttp(HttpStatusCode.BadRequest, error));
        var ex = await Assert.ThrowsAsync<InvalidRequestException>(() => client.CheckAsync("not-an-ip"));
        Assert.Equal(400, ex.StatusCode);
        Assert.Equal("invalid_ip", ex.ErrorCode);
    }

    [Fact]
    public async Task CheckAsync_401_ThrowsAuthenticationException()
    {
        var error = new { error = "invalid_api_key", message = "Invalid API key" };
        using var client = CreateClient(MockHttp(HttpStatusCode.Unauthorized, error));
        await Assert.ThrowsAsync<AuthenticationException>(() => client.CheckAsync("8.8.8.8"));
    }

    [Fact]
    public async Task CheckAsync_429_ThrowsRateLimitException()
    {
        var error = new { error = "rate_limit_exceeded", message = "Limit exceeded", retry_after = 3600 };
        using var client = CreateClient(MockHttp(HttpStatusCode.TooManyRequests, error));
        var ex = await Assert.ThrowsAsync<RateLimitException>(() => client.CheckAsync("8.8.8.8"));
        Assert.Equal(429, ex.StatusCode);
        Assert.Equal(3600, ex.RetryAfter);
    }

    [Fact]
    public async Task CheckAsync_500_ThrowsServerException()
    {
        var error = new { error = "internal_error", message = "Server error" };
        using var client = CreateClient(MockHttp(HttpStatusCode.InternalServerError, error));
        await Assert.ThrowsAsync<ServerException>(() => client.CheckAsync("8.8.8.8"));
    }

    [Fact]
    public async Task CheckBatchAsync_ReturnsBatchResponse()
    {
        var mockResponse = new
        {
            results = new[]
            {
                new { ip = "185.220.101.1", fraud_score = 70 },
                new { ip = "8.8.8.8", fraud_score = 0 }
            }
        };

        using var client = CreateClient(MockHttp(HttpStatusCode.OK, mockResponse));
        var result = await client.CheckBatchAsync(new[] { "185.220.101.1", "8.8.8.8" });

        Assert.Equal(2, result.Results.Count);
        Assert.Equal(70, result.Results[0].FraudScore);
        Assert.Equal(0, result.Results[1].FraudScore);
    }

    [Fact]
    public async Task CheckBatchAsync_EmptyList_ThrowsArgumentException()
    {
        using var client = new VerifIPClient("vip_testkey");
        await Assert.ThrowsAsync<ArgumentException>(() => client.CheckBatchAsync(Array.Empty<string>()));
    }

    [Fact]
    public async Task CheckBatchAsync_Over100_ThrowsArgumentException()
    {
        using var client = new VerifIPClient("vip_testkey");
        var ips = Enumerable.Range(1, 101).Select(i => $"1.2.3.{i % 256}").ToList();
        await Assert.ThrowsAsync<ArgumentException>(() => client.CheckBatchAsync(ips));
    }

    [Fact]
    public async Task HealthAsync_ReturnsHealthResponse()
    {
        var mockResponse = new
        {
            status = "ok",
            version = "1.0.0",
            data_loaded_at = "2026-04-19T12:00:00Z",
            redis = "ok",
            postgres = "ok",
            uptime_seconds = 3600
        };

        using var client = CreateClient(MockHttp(HttpStatusCode.OK, mockResponse));
        var result = await client.HealthAsync();

        Assert.Equal("ok", result.Status);
        Assert.Equal("1.0.0", result.Version);
        Assert.Equal(3600, result.UptimeSeconds);
    }

    [Fact]
    public void Constructor_EmptyApiKey_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new VerifIPClient(""));
    }

    [Fact]
    public void ToString_ShowsBaseUrl()
    {
        using var client = new VerifIPClient("vip_testkey", new VerifIPClientOptions
        {
            BaseUrl = "http://localhost:8080"
        });
        Assert.Contains("localhost:8080", client.ToString());
    }
}

/// <summary>
/// Simple mock HTTP handler for testing.
/// </summary>
internal class MockHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly string _body;
    private readonly Dictionary<string, string>? _headers;

    public MockHandler(HttpStatusCode statusCode, string body, Dictionary<string, string>? headers = null)
    {
        _statusCode = statusCode;
        _body = body;
        _headers = headers;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_body, System.Text.Encoding.UTF8, "application/json")
        };

        if (_headers != null)
        {
            foreach (var (key, value) in _headers)
            {
                response.Headers.TryAddWithoutValidation(key, value);
            }
        }

        return Task.FromResult(response);
    }
}
