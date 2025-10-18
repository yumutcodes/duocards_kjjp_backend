using System.ComponentModel.DataAnnotations;

namespace FitnessApp.Api.Features.Auth.DTOs;

/// <summary>
/// Request DTO for revoking a refresh token (logout)
/// </summary>
public class RevokeTokenRequest
{
    /// <summary>
    /// The refresh token to revoke
    /// </summary>
    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; } = string.Empty;
}
