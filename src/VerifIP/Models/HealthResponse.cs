using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from the health check endpoint.
/// </summary>
public sealed class HealthResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    [JsonPropertyName("data_loaded_at")]
    public string DataLoadedAt { get; set; } = "";

    [JsonPropertyName("redis")]
    public string Redis { get; set; } = "";

    [JsonPropertyName("postgres")]
    public string Postgres { get; set; } = "";

    [JsonPropertyName("uptime_seconds")]
    public int UptimeSeconds { get; set; }
}
