using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Request body for the batch check endpoint.
/// </summary>
public sealed class BatchRequest
{
    [JsonPropertyName("ips")]
    public List<string> Ips { get; set; } = new();
}

/// <summary>
/// Response from a batch IP check.
/// </summary>
public sealed class BatchResponse
{
    [JsonPropertyName("results")]
    public List<CheckResponse> Results { get; set; } = new();
}
