using BCrypt.Net;

namespace FitnessApp.Api.Infrastructure.Services;

/// <summary>
/// Interface for password hashing operations
/// </summary>
public interface IPasswordHashingService
{
    /// <summary>
    /// Hashes a plain text password using BCrypt
    /// </summary>
    /// <param name="password">Plain text password</param>
    /// <returns>Hashed password</returns>
    string HashPassword(string password);

    /// <summary>
    /// Verifies a plain text password against a hashed password
    /// </summary>
    /// <param name="password">Plain text password to verify</param>
    /// <param name="hashedPassword">Previously hashed password</param>
    /// <returns>True if password matches, false otherwise</returns>
    bool VerifyPassword(string password, string hashedPassword);
}

/// <summary>
/// Service for secure password hashing using BCrypt algorithm
/// BCrypt is a password hashing function designed to be slow and computationally expensive
/// This makes it resistant to brute-force attacks
///
/// Key features:
/// - Automatically generates and includes salt
/// - Configurable work factor (cost)
/// - Industry-standard algorithm
/// - Protection against rainbow table attacks
/// </summary>
public class PasswordHashingService : IPasswordHashingService
{
    private readonly ILogger<PasswordHashingService> _logger;

    // Work factor for BCrypt (higher = more secure but slower)
    // 12 is a good balance between security and performance as of 2024
    // Each increment doubles the computation time
    private const int WorkFactor = 12;

    public PasswordHashingService(ILogger<PasswordHashingService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Hashes a password using BCrypt with automatic salt generation
    ///
    /// Process:
    /// 1. BCrypt generates a random salt
    /// 2. Salt and password are combined
    /// 3. Multiple rounds of hashing are applied (2^WorkFactor iterations)
    /// 4. Final hash includes the salt and work factor
    ///
    /// Example hash: $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    /// - $2a$ = BCrypt identifier
    /// - 12 = work factor
    /// - First 22 chars = salt
    /// - Remaining chars = hash
    /// </summary>
    /// <param name="password">Plain text password to hash</param>
    /// <returns>BCrypt hashed password (60 characters)</returns>
    public string HashPassword(string password)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
            }

            // HashPassword automatically generates a salt and applies the specified work factor
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);

            _logger.LogDebug("Password hashed successfully");

            return hashedPassword;
        }
        catch (ArgumentException)
        {
            // Re-throw argument exceptions
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error hashing password");
            throw new InvalidOperationException("An error occurred while hashing the password", ex);
        }
    }

    /// <summary>
    /// Verifies a plain text password against a BCrypt hash
    ///
    /// Process:
    /// 1. Extract salt and work factor from the stored hash
    /// 2. Hash the provided password with the extracted salt
    /// 3. Compare the new hash with the stored hash using constant-time comparison
    ///
    /// The comparison is done in constant time to prevent timing attacks
    /// where an attacker could determine if they're getting closer to the correct password
    /// based on how long the comparison takes
    /// </summary>
    /// <param name="password">Plain text password to verify</param>
    /// <param name="hashedPassword">Previously hashed password from database</param>
    /// <returns>True if the password matches the hash, false otherwise</returns>
    public bool VerifyPassword(string password, string hashedPassword)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                _logger.LogWarning("Password verification failed: Password is null or empty");
                return false;
            }

            if (string.IsNullOrWhiteSpace(hashedPassword))
            {
                _logger.LogWarning("Password verification failed: Hashed password is null or empty");
                return false;
            }

            // Verify returns true if password matches, false otherwise
            // Uses constant-time comparison to prevent timing attacks
            var isValid = BCrypt.Net.BCrypt.Verify(password, hashedPassword);

            if (isValid)
            {
                _logger.LogDebug("Password verification successful");
            }
            else
            {
                _logger.LogWarning("Password verification failed: Password does not match hash");
            }

            return isValid;
        }
        catch (Exception ex)
        {
            // BCrypt.Verify can throw SaltParseException if the hash is malformed
            _logger.LogError(ex, "Error verifying password");
            return false; // Return false on any error (invalid hash format, etc.)
        }
    }
}
