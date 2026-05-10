using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from an email risk check.
/// </summary>
public sealed class EmailResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("email")]
    public string Email { get; set; } = "";

    [JsonPropertyName("risk_score")]
    public int RiskScore { get; set; }

    [JsonPropertyName("valid_syntax")]
    public bool ValidSyntax { get; set; }

    [JsonPropertyName("mx_found")]
    public bool MxFound { get; set; }

    [JsonPropertyName("is_disposable")]
    public bool IsDisposable { get; set; }

    [JsonPropertyName("is_free_provider")]
    public bool IsFreeProvider { get; set; }

    [JsonPropertyName("is_role_based")]
    public bool IsRoleBased { get; set; }

    [JsonPropertyName("domain_age_days")]
    public int DomainAgeDays { get; set; }

    [JsonPropertyName("domain")]
    public string Domain { get; set; } = "";

    [JsonPropertyName("signal_breakdown")]
    public Dictionary<string, int>? SignalBreakdown { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}
