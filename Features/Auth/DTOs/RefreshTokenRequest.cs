using System.ComponentModel.DataAnnotations;

namespace FitnessApp.Api.Features.Auth.DTOs;

/// <summary>
/// Request DTO for refreshing an access token using a refresh token
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// The refresh token previously issued to the client
    /// </summary>
    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; } = string.Empty;
}
