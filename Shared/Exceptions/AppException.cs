namespace FitnessApp.Api.Shared.Exceptions;

/// <summary>
/// Base exception class for all application-specific exceptions
/// </summary>
public class AppException : Exception
{
    public int StatusCode { get; }
    public string ErrorCode { get; }

    public AppException(
        string message,
        int statusCode = 500,
        string errorCode = "INTERNAL_ERROR")
        : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }

    public AppException(
        string message,
        Exception innerException,
        int statusCode = 500,
        string errorCode = "INTERNAL_ERROR")
        : base(message, innerException)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }
}
