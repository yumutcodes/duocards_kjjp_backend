using System.Net;
using System.Text.Json;
using FitnessApp.Api.Shared.Exceptions;
using FitnessApp.Api.Shared.Models;

namespace FitnessApp.Api.Shared.Middleware;

/// <summary>
/// Global exception handling middleware
/// Catches all unhandled exceptions and converts them to standard ApiResponse format
/// </summary>
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;
    private readonly IWebHostEnvironment _environment;

    public ExceptionHandlingMiddleware(
        RequestDelegate next,
        ILogger<ExceptionHandlingMiddleware> logger,
        IWebHostEnvironment environment)
    {
        _next = next;
        _logger = logger;
        _environment = environment;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        _logger.LogError(exception, "An unhandled exception occurred: {Message}", exception.Message);

        context.Response.ContentType = "application/json";

        var response = exception switch
        {
            AppException appEx => CreateResponseFromAppException(appEx, context),
            _ => CreateGenericErrorResponse(exception, context)
        };

        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        await context.Response.WriteAsync(json);
    }

    private ApiResponse CreateResponseFromAppException(AppException exception, HttpContext context)
    {
        context.Response.StatusCode = exception.StatusCode;

        return ApiResponse.FailureResult(
            message: exception.Message,
            errorCode: exception.ErrorCode,
            errors: _environment.IsDevelopment() && exception.InnerException != null
                ? new List<string> { exception.InnerException.Message }
                : null
        );
    }

    private ApiResponse CreateGenericErrorResponse(Exception exception, HttpContext context)
    {
        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

        return ApiResponse.FailureResult(
            message: _environment.IsDevelopment()
                ? exception.Message
                : "An unexpected error occurred. Please try again later.",
            errorCode: "INTERNAL_SERVER_ERROR",
            errors: _environment.IsDevelopment() && exception.StackTrace != null
                ? new List<string> { exception.StackTrace }
                : null
        );
    }
}

/// <summary>
/// Extension method to register the middleware
/// </summary>
public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseExceptionHandlingMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ExceptionHandlingMiddleware>();
    }
}
