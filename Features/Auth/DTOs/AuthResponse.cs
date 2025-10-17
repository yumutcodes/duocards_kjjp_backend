namespace FitnessApp.Api.Features.Auth.DTOs;

/// <summary>
/// Response DTO returned after successful authentication
/// Contains user information and authentication tokens
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// JWT access token for API authentication
    /// Short-lived (typically 15-60 minutes)
    /// Must be included in Authorization header for protected endpoints
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Refresh token for obtaining new access tokens
    /// Long-lived (typically 7-30 days)
    /// Should be stored securely by the client
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Type of token (always "Bearer" for JWT)
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// When the access token expires (Unix timestamp)
    /// </summary>
    public long ExpiresIn { get; set; }

    /// <summary>
    /// User information
    /// </summary>
    public UserDto User { get; set; } = null!;
}

/// <summary>
/// User information DTO included in authentication responses
/// </summary>
public class UserDto
{
    /// <summary>
    /// User's unique identifier
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// User's email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// User's first name
    /// </summary>
    public string? FirstName { get; set; }

    /// <summary>
    /// User's last name
    /// </summary>
    public string? LastName { get; set; }

    /// <summary>
    /// URL to user's profile picture
    /// </summary>
    public string? ProfilePictureUrl { get; set; }

    /// <summary>
    /// Authentication provider used (Email, Google, etc.)
    /// </summary>
    public string AuthProvider { get; set; } = string.Empty;

    /// <summary>
    /// Whether the user's email is verified
    /// </summary>
    public bool IsEmailVerified { get; set; }

    /// <summary>
    /// When the user account was created
    /// </summary>
    public DateTime CreatedAt { get; set; }
}
