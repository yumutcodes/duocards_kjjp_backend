using System.Security.Claims;
using FitnessApp.Api.Shared.Constants;

namespace FitnessApp.Api.Shared.Extensions;

/// <summary>
/// Extension methods for HttpContext
/// </summary>
public static class HttpContextExtensions
{
    /// <summary>
    /// Gets the client's IP address from the request, handling reverse proxy scenarios
    /// </summary>
    public static string GetIpAddress(this HttpContext context)
    {
        // Check for X-Forwarded-For header (set by reverse proxies/load balancers)
        if (context.Request.Headers.ContainsKey(AppConstants.Headers.XForwardedFor))
        {
            var forwardedFor = context.Request.Headers[AppConstants.Headers.XForwardedFor].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                // X-Forwarded-For can contain multiple IPs, take the first one
                return forwardedFor.Split(',')[0].Trim();
            }
        }

        // Fallback to RemoteIpAddress
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    /// <summary>
    /// Gets the client's user agent string
    /// </summary>
    public static string? GetUserAgent(this HttpContext context)
    {
        return context.Request.Headers[AppConstants.Headers.UserAgent].FirstOrDefault();
    }

    /// <summary>
    /// Gets the current user ID from JWT claims
    /// </summary>
    public static Guid? GetUserId(this HttpContext context)
    {
        var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? context.User.FindFirst(AuthConstants.Claims.UserId)?.Value;

        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return null;
        }

        return userId;
    }

    /// <summary>
    /// Gets the current user's email from JWT claims
    /// </summary>
    public static string? GetUserEmail(this HttpContext context)
    {
        return context.User.FindFirst(ClaimTypes.Email)?.Value
            ?? context.User.FindFirst(AuthConstants.Claims.Email)?.Value;
    }
}
