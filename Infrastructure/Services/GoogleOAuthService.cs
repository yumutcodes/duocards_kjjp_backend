using Google.Apis.Auth;

namespace FitnessApp.Api.Infrastructure.Services;

/// <summary>
/// Result of Google token verification containing user information
/// </summary>
public class GoogleUserInfo
{
    /// <summary>
    /// Google user ID (unique identifier from Google)
    /// </summary>
    public string GoogleId { get; set; } = string.Empty;

    /// <summary>
    /// User's email address from Google account
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Whether the email has been verified by Google
    /// </summary>
    public bool EmailVerified { get; set; }

    /// <summary>
    /// User's first name (given name)
    /// </summary>
    public string? FirstName { get; set; }

    /// <summary>
    /// User's last name (family name)
    /// </summary>
    public string? LastName { get; set; }

    /// <summary>
    /// URL to user's profile picture from Google
    /// </summary>
    public string? ProfilePictureUrl { get; set; }
}

/// <summary>
/// Interface for Google OAuth operations
/// </summary>
public interface IGoogleOAuthService
{
    /// <summary>
    /// Verifies a Google ID token and returns user information
    /// </summary>
    /// <param name="idToken">Google ID token from client</param>
    /// <returns>Google user information if valid, null if invalid</returns>
    Task<GoogleUserInfo?> VerifyGoogleTokenAsync(string idToken);
}

/// <summary>
/// Service for Google OAuth authentication
/// Verifies Google ID tokens received from the client-side Google Sign-In
///
/// How it works:
/// 1. Client uses Google Sign-In SDK to authenticate user
/// 2. Client receives an ID token from Google
/// 3. Client sends this ID token to our backend
/// 4. Backend verifies the token with Google's public keys
/// 5. If valid, extract user information from the token
///
/// Security notes:
/// - Always verify tokens on the backend (never trust client-side verification)
/// - Tokens are verified against Google's public keys
/// - Tokens include audience (client ID) validation
/// - Tokens have expiration times
/// </summary>
public class GoogleOAuthService : IGoogleOAuthService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<GoogleOAuthService> _logger;

    public GoogleOAuthService(IConfiguration configuration, ILogger<GoogleOAuthService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Verifies a Google ID token and extracts user information
    ///
    /// Process:
    /// 1. Get Google Client ID from configuration
    /// 2. Use Google.Apis.Auth library to verify the token
    /// 3. Library automatically:
    ///    - Downloads Google's public keys
    ///    - Verifies the signature
    ///    - Checks expiration
    ///    - Validates audience (client ID)
    /// 4. Extract user information from the validated payload
    ///
    /// The ID token is a JWT that contains:
    /// - iss (issuer): accounts.google.com or https://accounts.google.com
    /// - sub (subject): Google user ID
    /// - aud (audience): Your Google Client ID
    /// - exp (expiration): Token expiration time
    /// - email: User's email
    /// - email_verified: Whether Google has verified the email
    /// - name: Full name
    /// - given_name: First name
    /// - family_name: Last name
    /// - picture: Profile picture URL
    /// </summary>
    /// <param name="idToken">Google ID token from the client</param>
    /// <returns>GoogleUserInfo if token is valid, null otherwise</returns>
    public async Task<GoogleUserInfo?> VerifyGoogleTokenAsync(string idToken)
    {
        try
        {
            // Get Google Client ID from configuration
            // This must match the client ID used in your frontend Google Sign-In
            var googleClientId = _configuration["Authentication:Google:ClientId"]
                ?? throw new InvalidOperationException("Google Client ID is not configured");

            _logger.LogDebug("Attempting to verify Google ID token");

            // Verify the token using Google's library
            // This library:
            // 1. Downloads Google's public certificates (cached automatically)
            // 2. Verifies the token signature
            // 3. Checks that the token hasn't expired
            // 4. Validates that the audience matches our client ID
            var validationSettings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { googleClientId }
            };

            // ValidateAsync will throw an exception if the token is invalid
            var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, validationSettings);

            // If we get here, the token is valid
            _logger.LogInformation("Successfully verified Google token for user {Email}", payload.Email);

            // Extract user information from the token payload
            var userInfo = new GoogleUserInfo
            {
                GoogleId = payload.Subject, // Subject is the Google user ID
                Email = payload.Email,
                EmailVerified = payload.EmailVerified,
                FirstName = payload.GivenName,
                LastName = payload.FamilyName,
                ProfilePictureUrl = payload.Picture
            };

            return userInfo;
        }
        catch (InvalidJwtException ex)
        {
            // Token signature is invalid or token is malformed
            _logger.LogWarning(ex, "Invalid Google ID token: {Message}", ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            // Other errors (network issues, configuration problems, etc.)
            _logger.LogError(ex, "Error verifying Google ID token");
            return null;
        }
    }
}
