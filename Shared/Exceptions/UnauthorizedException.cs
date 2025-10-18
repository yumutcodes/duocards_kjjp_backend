namespace FitnessApp.Api.Shared.Exceptions;

/// <summary>
/// Exception thrown when authentication fails
/// HTTP Status Code: 401 Unauthorized
/// </summary>
public class UnauthorizedException : AppException
{
    public UnauthorizedException(string message = "Authentication failed", string errorCode = "UNAUTHORIZED")
        : base(message, statusCode: 401, errorCode: errorCode)
    {
    }

    public UnauthorizedException(string message, Exception innerException, string errorCode = "UNAUTHORIZED")
        : base(message, innerException, statusCode: 401, errorCode: errorCode)
    {
    }
}
