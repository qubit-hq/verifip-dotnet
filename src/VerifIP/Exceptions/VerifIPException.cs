namespace VerifIP.Exceptions;

/// <summary>
/// Base exception for all VerifIP API errors.
/// </summary>
public class VerifIPException : Exception
{
    public int StatusCode { get; }
    public string ErrorCode { get; }
    public int? RetryAfter { get; }

    public VerifIPException(string message, int statusCode = 0, string errorCode = "", int? retryAfter = null)
        : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
        RetryAfter = retryAfter;
    }
}

/// <summary>Thrown on 401 (invalid API key) or 403 (key disabled).</summary>
public class AuthenticationException : VerifIPException
{
    public AuthenticationException(string message, int statusCode, string errorCode)
        : base(message, statusCode, errorCode) { }
}

/// <summary>Thrown on 429 (rate limit exceeded).</summary>
public class RateLimitException : VerifIPException
{
    public RateLimitException(string message, int statusCode, string errorCode, int? retryAfter)
        : base(message, statusCode, errorCode, retryAfter) { }
}

/// <summary>Thrown on 400 (invalid IP, bad request).</summary>
public class InvalidRequestException : VerifIPException
{
    public InvalidRequestException(string message, int statusCode, string errorCode)
        : base(message, statusCode, errorCode) { }
}

/// <summary>Thrown on 5xx server errors.</summary>
public class ServerException : VerifIPException
{
    public ServerException(string message, int statusCode, string errorCode)
        : base(message, statusCode, errorCode) { }
}
