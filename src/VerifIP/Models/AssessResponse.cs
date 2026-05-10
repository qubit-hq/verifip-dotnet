using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from a unified risk assessment.
/// </summary>
public sealed class AssessResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("overall_risk")]
    public int OverallRisk { get; set; }

    [JsonPropertyName("ip")]
    public CheckResponse? Ip { get; set; }

    [JsonPropertyName("email")]
    public EmailResponse? Email { get; set; }

    [JsonPropertyName("phone")]
    public PhoneResponse? Phone { get; set; }

    [JsonPropertyName("url")]
    public UrlResponse? Url { get; set; }
}
