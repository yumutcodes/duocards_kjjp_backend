namespace FitnessApp.Api.Shared.Exceptions;

/// <summary>
/// Exception thrown when request validation fails or business rules are violated
/// HTTP Status Code: 400 Bad Request
/// </summary>
public class BadRequestException : AppException
{
    public BadRequestException(string message, string errorCode = "BAD_REQUEST")
        : base(message, statusCode: 400, errorCode: errorCode)
    {
    }

    public BadRequestException(string message, Exception innerException, string errorCode = "BAD_REQUEST")
        : base(message, innerException, statusCode: 400, errorCode: errorCode)
    {
    }
}
