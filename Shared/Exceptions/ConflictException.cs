namespace FitnessApp.Api.Shared.Exceptions;

/// <summary>
/// Exception thrown when there's a conflict with existing data (e.g., duplicate email)
/// HTTP Status Code: 409 Conflict
/// </summary>
public class ConflictException : AppException
{
    public ConflictException(string message = "Resource conflict", string errorCode = "CONFLICT")
        : base(message, statusCode: 409, errorCode: errorCode)
    {
    }

    public ConflictException(string message, Exception innerException, string errorCode = "CONFLICT")
        : base(message, innerException, statusCode: 409, errorCode: errorCode)
    {
    }
}
