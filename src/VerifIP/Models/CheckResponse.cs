using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from a single IP fraud check.
/// </summary>
public sealed class CheckResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("ip")]
    public string Ip { get; set; } = "";

    [JsonPropertyName("fraud_score")]
    public int FraudScore { get; set; }

    [JsonPropertyName("is_proxy")]
    public bool IsProxy { get; set; }

    [JsonPropertyName("is_vpn")]
    public bool IsVpn { get; set; }

    [JsonPropertyName("is_tor")]
    public bool IsTor { get; set; }

    [JsonPropertyName("is_datacenter")]
    public bool IsDatacenter { get; set; }

    [JsonPropertyName("country_code")]
    public string CountryCode { get; set; } = "";

    [JsonPropertyName("country_name")]
    public string CountryName { get; set; } = "";

    [JsonPropertyName("region")]
    public string Region { get; set; } = "";

    [JsonPropertyName("city")]
    public string City { get; set; } = "";

    [JsonPropertyName("isp")]
    public string Isp { get; set; } = "";

    [JsonPropertyName("asn")]
    public uint Asn { get; set; }

    [JsonPropertyName("connection_type")]
    public string ConnectionType { get; set; } = "";

    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = "";

    [JsonPropertyName("signal_breakdown")]
    public Dictionary<string, int>? SignalBreakdown { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}
