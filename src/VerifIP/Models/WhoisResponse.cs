using System.Text.Json.Serialization;

namespace VerifIP.Models;

/// <summary>
/// Response from a WHOIS lookup.
/// </summary>
public sealed class WhoisResponse
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("ip")]
    public string Ip { get; set; } = "";

    [JsonPropertyName("network_cidr")]
    public string NetworkCidr { get; set; } = "";

    [JsonPropertyName("network_name")]
    public string NetworkName { get; set; } = "";

    [JsonPropertyName("org_name")]
    public string OrgName { get; set; } = "";

    [JsonPropertyName("abuse_contact")]
    public string AbuseContact { get; set; } = "";

    [JsonPropertyName("rir")]
    public string Rir { get; set; } = "";

    [JsonPropertyName("allocation_date")]
    public string AllocationDate { get; set; } = "";

    [JsonPropertyName("country_code")]
    public string CountryCode { get; set; } = "";

    [JsonPropertyName("asn")]
    public int Asn { get; set; }

    [JsonPropertyName("asn_org")]
    public string AsnOrg { get; set; } = "";
}
