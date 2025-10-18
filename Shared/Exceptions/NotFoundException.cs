namespace FitnessApp.Api.Shared.Exceptions;

/// <summary>
/// Exception thrown when a requested resource is not found
/// HTTP Status Code: 404 Not Found
/// </summary>
public class NotFoundException : AppException
{
    public NotFoundException(string message = "Resource not found", string errorCode = "NOT_FOUND")
        : base(message, statusCode: 404, errorCode: errorCode)
    {
    }

    public NotFoundException(string message, Exception innerException, string errorCode = "NOT_FOUND")
        : base(message, innerException, statusCode: 404, errorCode: errorCode)
    {
    }
}
