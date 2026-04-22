using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using VerifIP.Exceptions;
using VerifIP.Models;

namespace VerifIP;

/// <summary>
/// Client for the VerifIP IP fraud risk scoring API.
/// </summary>
/// <example>
/// <code>
/// var client = new VerifIPClient("vip_your_key");
/// var result = await client.CheckAsync("185.220.101.1");
/// Console.WriteLine(result.FraudScore); // 70
/// </code>
/// </example>
public sealed class VerifIPClient : IDisposable
{
    private const string SdkVersion = "0.1.4";
    private static readonly int[] RetryableStatusCodes = { 429, 500, 502, 503, 504 };

    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly int _maxRetries;
    private readonly bool _ownsHttpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    private volatile RateLimitInfo? _rateLimit;

    /// <summary>Most recently observed rate limit info.</summary>
    public RateLimitInfo? RateLimit => _rateLimit;

    /// <summary>
    /// Creates a new VerifIP client.
    /// </summary>
    /// <param name="apiKey">Your API key (starts with vip_).</param>
    /// <param name="options">Optional client configuration.</param>
    public VerifIPClient(string apiKey, VerifIPClientOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("apiKey is required", nameof(apiKey));

        _apiKey = apiKey;
        options ??= new VerifIPClientOptions();
        _maxRetries = options.MaxRetries;

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        if (options.HttpClient != null)
        {
            _httpClient = options.HttpClient;
            _ownsHttpClient = false;
        }
        else
        {
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri(options.BaseUrl.TrimEnd('/')),
                Timeout = options.Timeout
            };
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"verifip-dotnet/{SdkVersion}");
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _ownsHttpClient = true;
        }
    }

    /// <summary>
    /// Check a single IP address for fraud risk.
    /// </summary>
    /// <param name="ip">IPv4 or IPv6 address.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Check response with fraud score and threat flags.</returns>
    public async Task<CheckResponse> CheckAsync(string ip, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ip))
            throw new ArgumentException("ip is required", nameof(ip));

        var encoded = Uri.EscapeDataString(ip);
        return await RequestAsync<CheckResponse>(HttpMethod.Get, $"/v1/check?ip={encoded}", null, true, cancellationToken);
    }

    /// <summary>
    /// Check multiple IP addresses in a single request. Requires Starter plan or higher.
    /// </summary>
    /// <param name="ips">List of IPs (1-100).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<BatchResponse> CheckBatchAsync(IReadOnlyList<string> ips, CancellationToken cancellationToken = default)
    {
        if (ips == null || ips.Count == 0)
            throw new ArgumentException("ips list is required and cannot be empty", nameof(ips));
        if (ips.Count > 100)
            throw new ArgumentException("Maximum 100 IPs per batch request", nameof(ips));

        var body = JsonSerializer.Serialize(new BatchRequest { Ips = ips.ToList() }, _jsonOptions);
        return await RequestAsync<BatchResponse>(HttpMethod.Post, "/v1/check/batch", body, true, cancellationToken);
    }

    /// <summary>
    /// Check API server health. Does not require authentication.
    /// </summary>
    public async Task<HealthResponse> HealthAsync(CancellationToken cancellationToken = default)
    {
        return await RequestAsync<HealthResponse>(HttpMethod.Get, "/health", null, false, cancellationToken);
    }

    private async Task<T> RequestAsync<T>(
        HttpMethod method,
        string path,
        string? body,
        bool auth,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;

        for (int attempt = 0; attempt <= _maxRetries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(method, path);
            if (auth)
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
            if (body != null)
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.SendAsync(request, cancellationToken);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                lastException = new VerifIPException("Connection error: network request failed");
                if (attempt < _maxRetries)
                {
                    await DelayAsync(attempt, null, cancellationToken);
                    continue;
                }
                throw lastException;
            }

            // Ensure response is disposed in all code paths
            using (response)
            {
                // Parse rate limit headers
                var rateLimitInfo = RateLimitInfo.FromHeaders(response);
                if (rateLimitInfo != null)
                    _rateLimit = rateLimitInfo;

                var content = await response.Content.ReadAsStringAsync(cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    if (string.IsNullOrEmpty(content))
                        throw new VerifIPException("Empty response body from server", 200);

                    try
                    {
                        return JsonSerializer.Deserialize<T>(content, _jsonOptions)
                            ?? throw new VerifIPException("Failed to deserialize response");
                    }
                    catch (JsonException ex)
                    {
                        throw new VerifIPException($"Invalid JSON response: {ex.Message}", 200);
                    }
                }

                // Error response
                var statusCode = (int)response.StatusCode;

                string errorCode = "";
                string message = content;
                int? retryAfter = null;

                try
                {
                    using var errorDoc = JsonDocument.Parse(content);
                    var root = errorDoc.RootElement;
                    if (root.TryGetProperty("error", out var e)) errorCode = e.GetString() ?? "";
                    if (root.TryGetProperty("message", out var m)) message = m.GetString() ?? content;
                    if (root.TryGetProperty("retry_after", out var r))
                    {
                        if (r.ValueKind == JsonValueKind.Number)
                            retryAfter = r.GetInt32();
                        else if (r.ValueKind == JsonValueKind.String && int.TryParse(r.GetString(), out var seconds))
                            retryAfter = seconds;
                    }
                }
                catch (JsonException)
                {
                    // Non-JSON error body (e.g., HTML from gateway) — truncate for safety
                    if (message.Length > 200)
                        message = message[..200] + "...";
                }

                var exception = CreateException(statusCode, errorCode, message, retryAfter);

                if (RetryableStatusCodes.Contains(statusCode) && attempt < _maxRetries)
                {
                    lastException = exception;
                    await DelayAsync(attempt, retryAfter, cancellationToken);
                    continue;
                }

                throw exception;
            }
        }

        throw lastException ?? new VerifIPException("Request failed after retries");
    }

    private static async Task DelayAsync(int attempt, int? retryAfter, CancellationToken ct)
    {
        var delay = retryAfter.HasValue
            ? Math.Min(retryAfter.Value, 30)
            : Math.Min(0.5 * Math.Pow(2, attempt), 30);
        var jitter = Random.Shared.NextDouble() * 0.25 * delay;
        await Task.Delay(TimeSpan.FromSeconds(delay + jitter), ct);
    }

    private static VerifIPException CreateException(int status, string code, string message, int? retryAfter)
    {
        return status switch
        {
            400 => new InvalidRequestException(message, status, code),
            401 or 403 => new AuthenticationException(message, status, code),
            429 => new RateLimitException(message, status, code, retryAfter),
            >= 500 => new ServerException(message, status, code),
            _ => new VerifIPException(message, status, code, retryAfter)
        };
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    public override string ToString() => $"VerifIPClient(baseUrl={_httpClient.BaseAddress})";
}

/// <summary>
/// Configuration options for <see cref="VerifIPClient"/>.
/// </summary>
public sealed class VerifIPClientOptions
{
    /// <summary>API base URL. Defaults to https://api.verifip.com.</summary>
    public string BaseUrl { get; set; } = "https://api.verifip.com";

    /// <summary>Request timeout. Defaults to 30 seconds.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Maximum retry attempts on 429/5xx. Defaults to 3.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Optional custom HttpClient. If provided, BaseUrl and Timeout are ignored.</summary>
    public HttpClient? HttpClient { get; set; }
}
