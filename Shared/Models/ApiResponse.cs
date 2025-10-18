namespace FitnessApp.Api.Shared.Models;

/// <summary>
/// Standard API response wrapper for all endpoints
/// Provides consistent response structure across the application
/// </summary>
/// <typeparam name="T">The type of data being returned</typeparam>
public class ApiResponse<T>
{
    /// <summary>
    /// Indicates whether the request was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Human-readable message about the operation result
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// The actual data payload (null if request failed)
    /// </summary>
    public T? Data { get; set; }

    /// <summary>
    /// Error code for failed requests (null if successful)
    /// </summary>
    public string? ErrorCode { get; set; }

    /// <summary>
    /// List of validation errors or additional error details
    /// </summary>
    public List<string>? Errors { get; set; }

    /// <summary>
    /// Timestamp when the response was generated
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Creates a successful response with data
    /// </summary>
    public static ApiResponse<T> SuccessResult(T data, string? message = null)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Data = data,
            Message = message ?? "Operation completed successfully"
        };
    }

    /// <summary>
    /// Creates a successful response without data
    /// </summary>
    public static ApiResponse<T> SuccessResult(string message)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Message = message
        };
    }

    /// <summary>
    /// Creates a failure response with error details
    /// </summary>
    public static ApiResponse<T> FailureResult(string message, string? errorCode = null, List<string>? errors = null)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            ErrorCode = errorCode,
            Errors = errors
        };
    }

    /// <summary>
    /// Creates a validation error response
    /// </summary>
    public static ApiResponse<T> ValidationErrorResult(List<string> errors)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = "Validation failed",
            ErrorCode = "VALIDATION_ERROR",
            Errors = errors
        };
    }
}

/// <summary>
/// Non-generic version for responses without data
/// </summary>
public class ApiResponse : ApiResponse<object>
{
    /// <summary>
    /// Creates a successful response without data
    /// </summary>
    public static new ApiResponse SuccessResult(string message)
    {
        return new ApiResponse
        {
            Success = true,
            Message = message
        };
    }

    /// <summary>
    /// Creates a failure response
    /// </summary>
    public static new ApiResponse FailureResult(string message, string? errorCode = null, List<string>? errors = null)
    {
        return new ApiResponse
        {
            Success = false,
            Message = message,
            ErrorCode = errorCode,
            Errors = errors
        };
    }
}
