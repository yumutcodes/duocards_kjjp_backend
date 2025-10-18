namespace FitnessApp.Api.Shared.Exceptions;

/// <summary>
/// Exception thrown when user doesn't have permission to access a resource
/// HTTP Status Code: 403 Forbidden
/// </summary>
public class ForbiddenException : AppException
{
    public ForbiddenException(string message = "Access forbidden", string errorCode = "FORBIDDEN")
        : base(message, statusCode: 403, errorCode: errorCode)
    {
    }

    public ForbiddenException(string message, Exception innerException, string errorCode = "FORBIDDEN")
        : base(message, innerException, statusCode: 403, errorCode: errorCode)
    {
    }
}
