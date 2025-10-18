namespace FitnessApp.Api.Shared.Constants;

/// <summary>
/// Authentication-related constants
/// </summary>
public static class AuthConstants
{
    /// <summary>
    /// Authentication provider names
    /// </summary>
    public static class Providers
    {
        public const string Email = "Email";
        public const string Google = "Google";
    }

    /// <summary>
    /// JWT claim types
    /// </summary>
    public static class Claims
    {
        public const string UserId = "sub";
        public const string Email = "email";
        public const string AuthProvider = "auth_provider";
    }

    /// <summary>
    /// Token expiration defaults (in case config is missing)
    /// </summary>
    public static class TokenExpiration
    {
        public const int DefaultAccessTokenMinutes = 60;
        public const int DefaultRefreshTokenDays = 7;
    }

    /// <summary>
    /// Error codes for authentication failures
    /// </summary>
    public static class ErrorCodes
    {
        public const string InvalidCredentials = "INVALID_CREDENTIALS";
        public const string EmailAlreadyExists = "EMAIL_ALREADY_EXISTS";
        public const string InvalidToken = "INVALID_TOKEN";
        public const string TokenExpired = "TOKEN_EXPIRED";
        public const string AccountInactive = "ACCOUNT_INACTIVE";
        public const string InvalidGoogleToken = "INVALID_GOOGLE_TOKEN";
    }

    /// <summary>
    /// Validation error messages
    /// </summary>
    public static class ValidationMessages
    {
        public const string EmailRequired = "Email is required";
        public const string EmailInvalid = "Invalid email format";
        public const string PasswordRequired = "Password is required";
        public const string PasswordMinLength = "Password must be at least 8 characters long";
        public const string PasswordsDoNotMatch = "Passwords do not match";
    }
}
