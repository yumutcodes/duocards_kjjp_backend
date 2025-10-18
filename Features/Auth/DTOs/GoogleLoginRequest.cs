using System.ComponentModel.DataAnnotations;

namespace FitnessApp.Api.Features.Auth.DTOs;

/// <summary>
/// Request DTO for Google OAuth authentication
/// </summary>
public class GoogleLoginRequest
{
    /// <summary>
    /// Google ID token received from the Google Sign-In client
    /// This token is verified on the backend to authenticate the user
    /// </summary>
    [Required(ErrorMessage = "Google ID token is required")]
    public string IdToken { get; set; } = string.Empty;
}
