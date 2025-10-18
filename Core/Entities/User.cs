using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FitnessApp.Api.Core.Entities;

/// <summary>
/// Represents a user in the fitness application.
/// Supports both email/password authentication and OAuth providers (Google).
/// </summary>
[Table("users")]
public class User
{
    /// <summary>
    /// Unique identifier for the user (Primary Key)
    /// </summary>
    [Key]
    [Column("id")]
    public Guid Id { get; set; }

    /// <summary>
    /// User's email address - used as username for login
    /// Must be unique across all users
    /// </summary>
    [Required]
    [MaxLength(255)]
    [Column("email")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Hashed password using BCrypt
    /// Null for OAuth-only users (e.g., Google sign-in without password)
    /// </summary>
    [Column("password_hash")]
    [MaxLength(255)]
    public string? PasswordHash { get; set; }

    /// <summary>
    /// User's first name
    /// </summary>
    [MaxLength(100)]
    [Column("first_name")]
    public string? FirstName { get; set; }

    /// <summary>
    /// User's last name
    /// </summary>
    [MaxLength(100)]
    [Column("last_name")]
    public string? LastName { get; set; }

    /// <summary>
    /// URL to user's profile picture
    /// Can be from OAuth provider or uploaded by user
    /// </summary>
    [MaxLength(500)]
    [Column("profile_picture_url")]
    public string? ProfilePictureUrl { get; set; }

    /// <summary>
    /// OAuth provider used for authentication (e.g., "Google", "Email")
    /// "Email" indicates traditional email/password authentication
    /// </summary>
    [Required]
    [MaxLength(50)]
    [Column("auth_provider")]
    public string AuthProvider { get; set; } = "Email";

    /// <summary>
    /// Unique identifier from the OAuth provider (e.g., Google User ID)
    /// Null for email/password users
    /// </summary>
    [MaxLength(255)]
    [Column("provider_user_id")]
    public string? ProviderUserId { get; set; }

    /// <summary>
    /// Indicates whether the user's email has been verified
    /// True by default for OAuth users
    /// False initially for email/password users (would be used for email verification feature)
    /// </summary>
    [Column("is_email_verified")]
    public bool IsEmailVerified { get; set; } = false;

    /// <summary>
    /// Indicates whether the user account is active
    /// Can be set to false to soft-delete or suspend accounts
    /// </summary>
    [Column("is_active")]
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Timestamp when the user account was created
    /// </summary>
    [Column("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Timestamp when the user account was last updated
    /// </summary>
    [Column("updated_at")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Timestamp of the user's last login
    /// Updated on every successful authentication
    /// </summary>
    [Column("last_login_at")]
    public DateTime? LastLoginAt { get; set; }

    /// <summary>
    /// Navigation property for refresh tokens
    /// One user can have multiple refresh tokens (different devices/sessions)
    /// </summary>
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
