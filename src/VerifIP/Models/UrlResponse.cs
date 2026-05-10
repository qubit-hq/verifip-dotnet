using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from a URL reputation check.
/// </summary>
public sealed class UrlResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("risk_score")]
    public int RiskScore { get; set; }

    [JsonPropertyName("is_phishing")]
    public bool IsPhishing { get; set; }

    [JsonPropertyName("is_malware")]
    public bool IsMalware { get; set; }

    [JsonPropertyName("safe_browsing_threat")]
    public string SafeBrowsingThreat { get; set; } = "";

    [JsonPropertyName("in_phishtank")]
    public bool InPhishtank { get; set; }

    [JsonPropertyName("spamhaus_dbl")]
    public bool SpamhausDbl { get; set; }

    [JsonPropertyName("domain_age_days")]
    public int DomainAgeDays { get; set; }

    [JsonPropertyName("ssl_valid")]
    public bool SslValid { get; set; }

    [JsonPropertyName("ssl_issuer")]
    public string SslIssuer { get; set; } = "";

    [JsonPropertyName("signal_breakdown")]
    public Dictionary<string, int>? SignalBreakdown { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}
