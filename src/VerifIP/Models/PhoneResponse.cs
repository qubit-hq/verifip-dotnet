using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from a phone number risk check.
/// </summary>
public sealed class PhoneResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("phone")]
    public string Phone { get; set; } = "";

    [JsonPropertyName("risk_score")]
    public int RiskScore { get; set; }

    [JsonPropertyName("valid_format")]
    public bool ValidFormat { get; set; }

    [JsonPropertyName("line_type")]
    public string LineType { get; set; } = "";

    [JsonPropertyName("carrier")]
    public string Carrier { get; set; } = "";

    [JsonPropertyName("country_code")]
    public string CountryCode { get; set; } = "";

    [JsonPropertyName("is_voip")]
    public bool IsVoip { get; set; }

    [JsonPropertyName("signal_breakdown")]
    public Dictionary<string, int>? SignalBreakdown { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}
