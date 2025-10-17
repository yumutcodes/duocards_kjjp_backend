using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FitnessApp.Api.Core.Entities;
using Microsoft.IdentityModel.Tokens;

namespace FitnessApp.Api.Infrastructure.Services;

/// <summary>
/// Interface for JWT token generation and validation
/// </summary>
public interface IJwtTokenService
{
    /// <summary>
    /// Generates a JWT access token for the specified user
    /// </summary>
    /// <param name="user">The user to generate the token for</param>
    /// <returns>JWT access token string</returns>
    string GenerateAccessToken(User user);

    /// <summary>
    /// Generates a cryptographically secure refresh token
    /// </summary>
    /// <returns>Refresh token string</returns>
    string GenerateRefreshToken();

    /// <summary>
    /// Validates a JWT access token and returns the principal
    /// </summary>
    /// <param name="token">The JWT token to validate</param>
    /// <returns>ClaimsPrincipal if valid, null if invalid</returns>
    ClaimsPrincipal? ValidateAccessToken(string token);

    /// <summary>
    /// Gets the user ID from a JWT token without full validation
    /// Useful for refresh token operations
    /// </summary>
    /// <param name="token">The JWT token</param>
    /// <returns>User ID if found, null otherwise</returns>
    Guid? GetUserIdFromToken(string token);
}

/// <summary>
/// Service for generating and validating JWT tokens
/// Implements secure token generation with configurable expiration
/// </summary>
public class JwtTokenService : IJwtTokenService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<JwtTokenService> _logger;

    public JwtTokenService(IConfiguration configuration, ILogger<JwtTokenService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Generates a JWT access token containing user claims
    /// Token is signed with HMAC-SHA256 and includes:
    /// - User ID (sub claim)
    /// - Email (email claim)
    /// - Unique token ID (jti)
    /// - Issued at (iat)
    /// - Expiration (exp)
    /// </summary>
    public string GenerateAccessToken(User user)
    {
        try
        {
            var secretKey = _configuration["Jwt:SecretKey"]
                ?? throw new InvalidOperationException("JWT Secret Key is not configured");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Create claims for the user
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // Subject (User ID)
                new Claim(JwtRegisteredClaimNames.Email, user.Email), // Email
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID (unique identifier)
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()), // Issued at
                new Claim("auth_provider", user.AuthProvider), // Custom claim for auth provider
            };

            // Add optional claims
            if (!string.IsNullOrEmpty(user.FirstName))
            {
                claims.Add(new Claim(ClaimTypes.GivenName, user.FirstName));
            }

            if (!string.IsNullOrEmpty(user.LastName))
            {
                claims.Add(new Claim(ClaimTypes.Surname, user.LastName));
            }

            // Get token expiration from configuration (default: 60 minutes)
            var expirationMinutes = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "60");

            // Create the token
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: credentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            _logger.LogInformation("Generated access token for user {UserId}", user.Id);

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating access token for user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Generates a cryptographically secure random refresh token
    /// Uses RandomNumberGenerator for high entropy
    /// Returns a base64-encoded string
    /// </summary>
    public string GenerateRefreshToken()
    {
        try
        {
            // Generate 64 bytes of random data
            var randomBytes = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            // Convert to base64 string
            var refreshToken = Convert.ToBase64String(randomBytes);

            _logger.LogDebug("Generated new refresh token");

            return refreshToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating refresh token");
            throw;
        }
    }

    /// <summary>
    /// Validates a JWT access token and returns the claims principal
    /// Performs full validation including:
    /// - Signature validation
    /// - Expiration validation
    /// - Issuer validation
    /// - Audience validation
    /// </summary>
    public ClaimsPrincipal? ValidateAccessToken(string token)
    {
        try
        {
            var secretKey = _configuration["Jwt:SecretKey"]
                ?? throw new InvalidOperationException("JWT Secret Key is not configured");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                IssuerSigningKey = key,
                ClockSkew = TimeSpan.Zero // No tolerance for expiration
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            // Verify the token is a JWT and uses the correct algorithm
            if (validatedToken is JwtSecurityToken jwtToken &&
                jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                _logger.LogDebug("Successfully validated access token");
                return principal;
            }

            _logger.LogWarning("Token validation failed: Invalid algorithm");
            return null;
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogWarning("Token validation failed: Token expired");
            return null;
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Token validation failed: {Message}", ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            return null;
        }
    }

    /// <summary>
    /// Extracts the user ID from a JWT token without performing full validation
    /// Useful for refresh token scenarios where we need the user ID but don't need to validate expiration
    /// </summary>
    public Guid? GetUserIdFromToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Read the token without validation
            var jwtToken = tokenHandler.ReadJwtToken(token);

            // Get the subject claim (user ID)
            var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub);

            if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
            {
                return userId;
            }

            _logger.LogWarning("Could not extract user ID from token");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting user ID from token");
            return null;
        }
    }
}
