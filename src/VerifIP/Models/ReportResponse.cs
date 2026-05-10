using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from a fraud report submission.
/// </summary>
public sealed class ReportResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}
