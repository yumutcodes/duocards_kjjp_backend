using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FitnessApp.Api.Core.Entities;

/// <summary>
/// Represents a refresh token for JWT authentication.
/// Refresh tokens are long-lived tokens used to obtain new access tokens without requiring re-authentication.
/// Each user can have multiple refresh tokens (one per device/session).
/// </summary>
[Table("refresh_tokens")]
public class RefreshToken
{
    /// <summary>
    /// Unique identifier for the refresh token (Primary Key)
    /// </summary>
    [Key]
    [Column("id")]
    public Guid Id { get; set; }

    /// <summary>
    /// Foreign key to the User table
    /// Links this refresh token to a specific user
    /// </summary>
    [Required]
    [Column("user_id")]
    public Guid UserId { get; set; }

    /// <summary>
    /// The actual refresh token string
    /// This is a cryptographically secure random string
    /// Stored as a hash for security
    /// </summary>
    [Required]
    [MaxLength(500)]
    [Column("token")]
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// When the refresh token expires
    /// Typically set to 7-30 days from creation
    /// Expired tokens cannot be used to get new access tokens
    /// </summary>
    [Required]
    [Column("expires_at")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// When the refresh token was created
    /// </summary>
    [Column("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// IP address from which the token was created
    /// Useful for security auditing and detecting suspicious activity
    /// </summary>
    [MaxLength(50)]
    [Column("created_by_ip")]
    public string? CreatedByIp { get; set; }

    /// <summary>
    /// When the refresh token was revoked (if applicable)
    /// Null if the token is still valid
    /// Tokens are revoked on logout or when suspected of being compromised
    /// </summary>
    [Column("revoked_at")]
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// IP address from which the token was revoked
    /// Useful for security auditing
    /// </summary>
    [MaxLength(50)]
    [Column("revoked_by_ip")]
    public string? RevokedByIp { get; set; }

    /// <summary>
    /// Reason why the token was revoked
    /// Examples: "User logout", "Token rotation", "Security compromise"
    /// </summary>
    [MaxLength(200)]
    [Column("revoke_reason")]
    public string? RevokeReason { get; set; }

    /// <summary>
    /// If this token was used to create a new token (token rotation)
    /// Points to the new token that replaced this one
    /// </summary>
    [Column("replaced_by_token_id")]
    public Guid? ReplacedByTokenId { get; set; }

    /// <summary>
    /// User agent string from the client that created this token
    /// Useful for identifying the device/browser
    /// </summary>
    [MaxLength(500)]
    [Column("user_agent")]
    public string? UserAgent { get; set; }

    /// <summary>
    /// Navigation property to the User entity
    /// </summary>
    [ForeignKey(nameof(UserId))]
    public virtual User User { get; set; } = null!;

    /// <summary>
    /// Computed property - checks if the token is currently active and valid
    /// </summary>
    [NotMapped]
    public bool IsActive => RevokedAt == null && !IsExpired;

    /// <summary>
    /// Computed property - checks if the token has expired
    /// </summary>
    [NotMapped]
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
}
