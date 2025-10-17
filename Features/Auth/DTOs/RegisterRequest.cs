using System.ComponentModel.DataAnnotations;

namespace FitnessApp.Api.Features.Auth.DTOs;

/// <summary>
/// Request DTO for user registration with email and password
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// User's email address - will be used as username
    /// Must be a valid email format
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [MaxLength(255, ErrorMessage = "Email cannot exceed 255 characters")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// User's password
    /// Must be at least 8 characters long
    /// Should contain uppercase, lowercase, number, and special character for security
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
    [MaxLength(100, ErrorMessage = "Password cannot exceed 100 characters")]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Password confirmation - must match the password field
    /// </summary>
    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>
    /// User's first name (optional during registration)
    /// </summary>
    [MaxLength(100, ErrorMessage = "First name cannot exceed 100 characters")]
    public string? FirstName { get; set; }

    /// <summary>
    /// User's last name (optional during registration)
    /// </summary>
    [MaxLength(100, ErrorMessage = "Last name cannot exceed 100 characters")]
    public string? LastName { get; set; }
}
