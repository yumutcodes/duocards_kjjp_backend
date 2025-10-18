namespace FitnessApp.Api.Shared.Constants;

/// <summary>
/// General application constants
/// </summary>
public static class AppConstants
{
    /// <summary>
    /// Application information
    /// </summary>
    public static class App
    {
        public const string Name = "Fitness App API";
        public const string Version = "v1";
    }

    /// <summary>
    /// HTTP header names
    /// </summary>
    public static class Headers
    {
        public const string Authorization = "Authorization";
        public const string Bearer = "Bearer";
        public const string XForwardedFor = "X-Forwarded-For";
        public const string UserAgent = "User-Agent";
    }

    /// <summary>
    /// CORS policy names
    /// </summary>
    public static class Cors
    {
        public const string AllowAll = "AllowAll";
        public const string Production = "Production";
    }

    /// <summary>
    /// Common validation rules
    /// </summary>
    public static class Validation
    {
        public const int MaxEmailLength = 255;
        public const int MaxNameLength = 100;
        public const int MinPasswordLength = 8;
        public const int MaxPasswordLength = 100;
    }
}
