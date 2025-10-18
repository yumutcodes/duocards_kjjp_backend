using FitnessApp.Api.Core.Entities;
using FitnessApp.Api.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace FitnessApp.Api.Infrastructure.Repositories;

/// <summary>
/// Interface for authentication-related database operations
/// Follows Repository pattern to abstract data access logic
/// </summary>
public interface IAuthRepository
{
    // User operations
    Task<User?> GetUserByIdAsync(Guid userId);
    Task<User?> GetUserByEmailAsync(string email);
    Task<User?> GetUserByProviderAsync(string provider, string providerUserId);
    Task<User> CreateUserAsync(User user);
    Task UpdateUserAsync(User user);
    Task<bool> EmailExistsAsync(string email);

    // Refresh token operations
    Task<RefreshToken?> GetRefreshTokenAsync(string token);
    Task<RefreshToken> CreateRefreshTokenAsync(RefreshToken refreshToken);
    Task UpdateRefreshTokenAsync(RefreshToken refreshToken);
    Task RevokeRefreshTokenAsync(RefreshToken refreshToken, string revokedByIp, string reason);
    Task RevokeAllUserRefreshTokensAsync(Guid userId, string revokedByIp, string reason);
    Task DeleteExpiredRefreshTokensAsync();
    Task<List<RefreshToken>> GetUserActiveRefreshTokensAsync(Guid userId);
}

/// <summary>
/// Repository for authentication-related database operations
/// Handles all database interactions for users and refresh tokens
///
/// Design patterns used:
/// - Repository Pattern: Encapsulates data access logic
/// - Async/Await: All operations are asynchronous for better scalability
/// - Separation of Concerns: Database logic separated from business logic
///
/// Benefits:
/// - Easier to test (can mock the repository)
/// - Cleaner business logic layer
/// - Centralized data access
/// - Easy to change database implementation
/// </summary>
public class AuthRepository : IAuthRepository
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AuthRepository> _logger;

    public AuthRepository(ApplicationDbContext context, ILogger<AuthRepository> logger)
    {
        _context = context;
        _logger = logger;
    }

    #region User Operations

    /// <summary>
    /// Gets a user by their unique ID
    /// Includes related refresh tokens for efficient queries
    /// </summary>
    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        try
        {
            return await _context.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Id == userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user by ID {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Gets a user by their email address
    /// Email is unique, so this returns a single user or null
    /// </summary>
    public async Task<User?> GetUserByEmailAsync(string email)
    {
        try
        {
            return await _context.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Email == email.ToLower());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user by email {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// Gets a user by their OAuth provider information
    /// Used for OAuth login (e.g., Google sign-in)
    /// </summary>
    /// <param name="provider">OAuth provider name (e.g., "Google")</param>
    /// <param name="providerUserId">User ID from the OAuth provider</param>
    public async Task<User?> GetUserByProviderAsync(string provider, string providerUserId)
    {
        try
        {
            return await _context.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u =>
                    u.AuthProvider == provider &&
                    u.ProviderUserId == providerUserId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user by provider {Provider} and ID {ProviderId}",
                provider, providerUserId);
            throw;
        }
    }

    /// <summary>
    /// Creates a new user in the database
    /// Sets default values and timestamps
    /// </summary>
    public async Task<User> CreateUserAsync(User user)
    {
        try
        {
            // Normalize email to lowercase for consistency
            user.Email = user.Email.ToLower();

            // Ensure timestamps are set
            user.CreatedAt = DateTime.UtcNow;
            user.UpdatedAt = DateTime.UtcNow;

            // Add to context
            await _context.Users.AddAsync(user);

            // Save changes to database
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created new user {UserId} with email {Email}", user.Id, user.Email);

            return user;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Database error creating user with email {Email}", user.Email);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user with email {Email}", user.Email);
            throw;
        }
    }

    /// <summary>
    /// Updates an existing user in the database
    /// UpdatedAt timestamp is automatically set by DbContext
    /// </summary>
    public async Task UpdateUserAsync(User user)
    {
        try
        {
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Updated user {UserId}", user.Id);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogError(ex, "Concurrency error updating user {UserId}", user.Id);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Checks if an email address already exists in the database
    /// Useful for validation during registration
    /// </summary>
    public async Task<bool> EmailExistsAsync(string email)
    {
        try
        {
            return await _context.Users
                .AnyAsync(u => u.Email == email.ToLower());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if email exists {Email}", email);
            throw;
        }
    }

    #endregion

    #region Refresh Token Operations

    /// <summary>
    /// Gets a refresh token by its token string
    /// Includes the related user for efficient queries
    /// </summary>
    public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        try
        {
            return await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting refresh token");
            throw;
        }
    }

    /// <summary>
    /// Creates a new refresh token in the database
    /// </summary>
    public async Task<RefreshToken> CreateRefreshTokenAsync(RefreshToken refreshToken)
    {
        try
        {
            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created new refresh token for user {UserId}", refreshToken.UserId);

            return refreshToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating refresh token for user {UserId}", refreshToken.UserId);
            throw;
        }
    }

    /// <summary>
    /// Updates an existing refresh token
    /// Used for token rotation and revocation
    /// </summary>
    public async Task UpdateRefreshTokenAsync(RefreshToken refreshToken)
    {
        try
        {
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            _logger.LogDebug("Updated refresh token {TokenId}", refreshToken.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating refresh token {TokenId}", refreshToken.Id);
            throw;
        }
    }

    /// <summary>
    /// Revokes a refresh token by marking it as revoked
    /// Does not delete the token (keep audit trail)
    /// </summary>
    /// <param name="refreshToken">The token to revoke</param>
    /// <param name="revokedByIp">IP address that initiated the revocation</param>
    /// <param name="reason">Reason for revocation</param>
    public async Task RevokeRefreshTokenAsync(RefreshToken refreshToken, string revokedByIp, string reason)
    {
        try
        {
            refreshToken.RevokedAt = DateTime.UtcNow;
            refreshToken.RevokedByIp = revokedByIp;
            refreshToken.RevokeReason = reason;

            await UpdateRefreshTokenAsync(refreshToken);

            _logger.LogInformation("Revoked refresh token {TokenId} for user {UserId}. Reason: {Reason}",
                refreshToken.Id, refreshToken.UserId, reason);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking refresh token {TokenId}", refreshToken.Id);
            throw;
        }
    }

    /// <summary>
    /// Revokes all active refresh tokens for a user
    /// Useful for security events (password change, suspicious activity, etc.)
    /// </summary>
    public async Task RevokeAllUserRefreshTokensAsync(Guid userId, string revokedByIp, string reason)
    {
        try
        {
            var activeTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && rt.RevokedAt == null)
                .ToListAsync();

            foreach (var token in activeTokens)
            {
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = revokedByIp;
                token.RevokeReason = reason;
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation("Revoked {Count} refresh tokens for user {UserId}. Reason: {Reason}",
                activeTokens.Count, userId, reason);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking all refresh tokens for user {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Deletes expired refresh tokens from the database
    /// Should be run periodically as a cleanup job
    /// Keeps the refresh_tokens table from growing indefinitely
    /// </summary>
    public async Task DeleteExpiredRefreshTokensAsync()
    {
        try
        {
            var expiredTokens = await _context.RefreshTokens
                .Where(rt => rt.ExpiresAt < DateTime.UtcNow)
                .ToListAsync();

            _context.RefreshTokens.RemoveRange(expiredTokens);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Deleted {Count} expired refresh tokens", expiredTokens.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting expired refresh tokens");
            throw;
        }
    }

    /// <summary>
    /// Gets all active (non-revoked, non-expired) refresh tokens for a user
    /// Useful for displaying active sessions to the user
    /// </summary>
    public async Task<List<RefreshToken>> GetUserActiveRefreshTokensAsync(Guid userId)
    {
        try
        {
            return await _context.RefreshTokens
                .Where(rt =>
                    rt.UserId == userId &&
                    rt.RevokedAt == null &&
                    rt.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(rt => rt.CreatedAt)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active refresh tokens for user {UserId}", userId);
            throw;
        }
    }

    #endregion
}
