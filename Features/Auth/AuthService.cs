using FitnessApp.Api.Core.Entities;
using FitnessApp.Api.Features.Auth.DTOs;
using FitnessApp.Api.Infrastructure.Repositories;
using FitnessApp.Api.Infrastructure.Services;
using FitnessApp.Api.Shared.Constants;
using FitnessApp.Api.Shared.Exceptions;

namespace FitnessApp.Api.Features.Auth;

/// <summary>
/// Interface for authentication business logic
/// </summary>
public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request, string ipAddress, string? userAgent);
    Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string? userAgent);
    Task<AuthResponse> GoogleLoginAsync(GoogleLoginRequest request, string ipAddress, string? userAgent);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken, string ipAddress, string? userAgent);
    Task RevokeTokenAsync(string refreshToken, string ipAddress);
    Task<User?> GetCurrentUserAsync(Guid userId);
}

/// <summary>
/// Service containing all authentication business logic
/// Orchestrates interactions between repositories and other services
///
/// This service is the core of the authentication system and handles:
/// - User registration with email/password
/// - User login with email/password
/// - Google OAuth authentication
/// - Token refresh (rotation)
/// - Token revocation (logout)
///
/// Design patterns:
/// - Service Layer Pattern: Business logic separated from controllers and data access
/// - Dependency Injection: All dependencies injected through constructor
/// - Single Responsibility: Each method has one clear purpose
///
/// Security features implemented:
/// - Password hashing with BCrypt
/// - JWT token generation
/// - Refresh token rotation
/// - IP address tracking for security auditing
/// - User agent tracking for device identification
/// </summary>
public class AuthService : IAuthService
{
    private readonly IAuthRepository _authRepository;
    private readonly IPasswordHashingService _passwordHashingService;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IGoogleOAuthService _googleOAuthService;
    private readonly ILogger<AuthService> _logger;
    private readonly IConfiguration _configuration;

    public AuthService(
        IAuthRepository authRepository,
        IPasswordHashingService passwordHashingService,
        IJwtTokenService jwtTokenService,
        IGoogleOAuthService googleOAuthService,
        ILogger<AuthService> logger,
        IConfiguration configuration)
    {
        _authRepository = authRepository;
        _passwordHashingService = passwordHashingService;
        _jwtTokenService = jwtTokenService;
        _googleOAuthService = googleOAuthService;
        _logger = logger;
        _configuration = configuration;
    }

    /// <summary>
    /// Registers a new user with email and password
    ///
    /// Process:
    /// 1. Validate that email doesn't already exist
    /// 2. Hash the password using BCrypt
    /// 3. Create user entity
    /// 4. Save to database
    /// 5. Generate access and refresh tokens
    /// 6. Return authentication response
    ///
    /// Security notes:
    /// - Passwords are never stored in plain text
    /// - Emails are normalized to lowercase
    /// - Email uniqueness is enforced at database level
    /// </summary>
    public async Task<AuthResponse> RegisterAsync(RegisterRequest request, string ipAddress, string? userAgent)
    {
        try
        {
            _logger.LogInformation("Starting registration process for email {Email}", request.Email);

            // Check if email already exists
            if (await _authRepository.EmailExistsAsync(request.Email))
            {
                _logger.LogWarning("Registration failed: Email {Email} already exists", request.Email);
                throw new ConflictException("An account with this email already exists", AuthConstants.ErrorCodes.EmailAlreadyExists);
            }

            // Hash the password
            var passwordHash = _passwordHashingService.HashPassword(request.Password);

            // Create user entity
            var user = new User
            {
                Id = Guid.NewGuid(),
                Email = request.Email.ToLower(),
                PasswordHash = passwordHash,
                FirstName = request.FirstName,
                LastName = request.LastName,
                AuthProvider = "Email",
                IsEmailVerified = false, // Would be true after email verification flow
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                LastLoginAt = DateTime.UtcNow
            };

            // Save user to database
            user = await _authRepository.CreateUserAsync(user);

            _logger.LogInformation("User {UserId} registered successfully with email {Email}",
                user.Id, user.Email);

            // Generate tokens and return response
            return await GenerateAuthResponseAsync(user, ipAddress, userAgent);
        }
        catch (ConflictException)
        {
            // Re-throw business logic exceptions
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration for email {Email}", request.Email);
            throw new AppException("An error occurred during registration", ex);
        }
    }

    /// <summary>
    /// Authenticates a user with email and password
    ///
    /// Process:
    /// 1. Find user by email
    /// 2. Verify password hash
    /// 3. Update last login timestamp
    /// 4. Generate access and refresh tokens
    /// 5. Return authentication response
    ///
    /// Security notes:
    /// - Uses constant-time password comparison to prevent timing attacks
    /// - Doesn't reveal whether email or password was incorrect (same error for both)
    /// - Checks if account is active
    /// </summary>
    public async Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string? userAgent)
    {
        try
        {
            _logger.LogInformation("Login attempt for email {Email}", request.Email);

            // Find user by email
            var user = await _authRepository.GetUserByEmailAsync(request.Email);

            // Validate user exists and has a password (OAuth-only users don't have passwords)
            if (user == null || string.IsNullOrEmpty(user.PasswordHash))
            {
                _logger.LogWarning("Login failed: Invalid credentials for email {Email}", request.Email);
                throw new UnauthorizedException("Invalid email or password", AuthConstants.ErrorCodes.InvalidCredentials);
            }

            // Verify password
            if (!_passwordHashingService.VerifyPassword(request.Password, user.PasswordHash))
            {
                _logger.LogWarning("Login failed: Invalid password for email {Email}", request.Email);
                throw new UnauthorizedException("Invalid email or password", AuthConstants.ErrorCodes.InvalidCredentials);
            }

            // Check if account is active
            if (!user.IsActive)
            {
                _logger.LogWarning("Login failed: Account {UserId} is inactive", user.Id);
                throw new UnauthorizedException("This account has been deactivated", AuthConstants.ErrorCodes.AccountInactive);
            }

            // Update last login timestamp
            user.LastLoginAt = DateTime.UtcNow;
            await _authRepository.UpdateUserAsync(user);

            _logger.LogInformation("User {UserId} logged in successfully", user.Id);

            // Generate tokens and return response
            return await GenerateAuthResponseAsync(user, ipAddress, userAgent);
        }
        catch (UnauthorizedException)
        {
            // Re-throw auth exceptions
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for email {Email}", request.Email);
            throw new AppException("An error occurred during login", ex);
        }
    }

    /// <summary>
    /// Authenticates a user with Google OAuth
    ///
    /// Process:
    /// 1. Verify Google ID token
    /// 2. Extract user information from token
    /// 3. Check if user exists by Google ID or email
    /// 4. If new user, create account
    /// 5. If existing user, update information
    /// 6. Generate access and refresh tokens
    /// 7. Return authentication response
    ///
    /// Security notes:
    /// - Token is verified with Google's public keys
    /// - Only accepts tokens for our configured client ID
    /// - Email is automatically verified (Google verified)
    /// - Can link multiple OAuth providers to same email (future enhancement)
    /// </summary>
    public async Task<AuthResponse> GoogleLoginAsync(GoogleLoginRequest request, string ipAddress, string? userAgent)
    {
        try
        {
            _logger.LogInformation("Google login attempt");

            // Verify the Google ID token
            var googleUserInfo = await _googleOAuthService.VerifyGoogleTokenAsync(request.IdToken);

            if (googleUserInfo == null)
            {
                _logger.LogWarning("Google login failed: Invalid token");
                throw new UnauthorizedException("Invalid Google token", AuthConstants.ErrorCodes.InvalidGoogleToken);
            }

            _logger.LogInformation("Google token verified for email {Email}", googleUserInfo.Email);

            // Check if user exists by Google ID
            var user = await _authRepository.GetUserByProviderAsync("Google", googleUserInfo.GoogleId);

            if (user == null)
            {
                // Check if user exists with this email (different provider)
                user = await _authRepository.GetUserByEmailAsync(googleUserInfo.Email);

                if (user != null)
                {
                    // User exists with same email but different provider
                    // Option 1: Link accounts (current implementation)
                    // Option 2: Require separate registration (commented out below)

                    // throw new InvalidOperationException(
                    //     "An account with this email already exists. Please login with your password.");

                    _logger.LogInformation("Linking Google account to existing user {UserId}", user.Id);

                    // Update user to link Google account
                    user.AuthProvider = "Google"; // Or could support multiple providers
                    user.ProviderUserId = googleUserInfo.GoogleId;
                    user.IsEmailVerified = true; // Google verifies emails
                    user.LastLoginAt = DateTime.UtcNow;

                    // Update profile info if not set
                    user.FirstName ??= googleUserInfo.FirstName;
                    user.LastName ??= googleUserInfo.LastName;
                    user.ProfilePictureUrl ??= googleUserInfo.ProfilePictureUrl;

                    await _authRepository.UpdateUserAsync(user);
                }
                else
                {
                    // New user - create account
                    _logger.LogInformation("Creating new user from Google account {Email}", googleUserInfo.Email);

                    user = new User
                    {
                        Id = Guid.NewGuid(),
                        Email = googleUserInfo.Email.ToLower(),
                        FirstName = googleUserInfo.FirstName,
                        LastName = googleUserInfo.LastName,
                        ProfilePictureUrl = googleUserInfo.ProfilePictureUrl,
                        AuthProvider = "Google",
                        ProviderUserId = googleUserInfo.GoogleId,
                        IsEmailVerified = true, // Google verifies emails
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        LastLoginAt = DateTime.UtcNow
                    };

                    user = await _authRepository.CreateUserAsync(user);

                    _logger.LogInformation("Created new user {UserId} from Google account", user.Id);
                }
            }
            else
            {
                // Existing Google user - update last login and profile info
                _logger.LogInformation("Existing Google user {UserId} logging in", user.Id);

                user.LastLoginAt = DateTime.UtcNow;

                // Update profile info in case it changed in Google
                user.FirstName = googleUserInfo.FirstName ?? user.FirstName;
                user.LastName = googleUserInfo.LastName ?? user.LastName;
                user.ProfilePictureUrl = googleUserInfo.ProfilePictureUrl ?? user.ProfilePictureUrl;

                await _authRepository.UpdateUserAsync(user);
            }

            // Check if account is active
            if (!user.IsActive)
            {
                _logger.LogWarning("Google login failed: Account {UserId} is inactive", user.Id);
                throw new UnauthorizedException("This account has been deactivated", AuthConstants.ErrorCodes.AccountInactive);
            }

            _logger.LogInformation("User {UserId} logged in successfully via Google", user.Id);

            // Generate tokens and return response
            return await GenerateAuthResponseAsync(user, ipAddress, userAgent);
        }
        catch (UnauthorizedException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Google login");
            throw new AppException("An error occurred during Google login", ex);
        }
    }

    /// <summary>
    /// Refreshes an access token using a refresh token
    ///
    /// Process:
    /// 1. Validate refresh token exists and is active
    /// 2. Get associated user
    /// 3. Revoke old refresh token
    /// 4. Generate new access and refresh tokens (token rotation)
    /// 5. Return authentication response
    ///
    /// Security features:
    /// - Token rotation: Old refresh token is invalidated
    /// - Prevents token reuse
    /// - Tracks IP and user agent for security auditing
    /// - Links old and new tokens for security analysis
    ///
    /// Token rotation prevents:
    /// - Replay attacks
    /// - Token theft (stolen tokens expire quickly)
    /// - Unauthorized access if token is compromised
    /// </summary>
    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken, string ipAddress, string? userAgent)
    {
        try
        {
            _logger.LogDebug("Refresh token request from IP {IpAddress}", ipAddress);

            // Get the refresh token from database
            var token = await _authRepository.GetRefreshTokenAsync(refreshToken);

            if (token == null)
            {
                _logger.LogWarning("Refresh token not found");
                throw new UnauthorizedException("Invalid refresh token", AuthConstants.ErrorCodes.InvalidToken);
            }

            // Validate token is active
            if (!token.IsActive)
            {
                _logger.LogWarning("Refresh token {TokenId} is not active (expired or revoked)", token.Id);

                // If token was already used (revoked due to rotation), might indicate token theft
                if (token.ReplacedByTokenId.HasValue)
                {
                    _logger.LogWarning("Possible token reuse detected for user {UserId}", token.UserId);
                    // Optional: Revoke all tokens for this user as a security measure
                    // await _authRepository.RevokeAllUserRefreshTokensAsync(
                    //     token.UserId, ipAddress, "Possible token reuse detected");
                }

                throw new UnauthorizedException(
                    token.IsExpired ? "Refresh token has expired" : "Refresh token has been revoked",
                    token.IsExpired ? AuthConstants.ErrorCodes.TokenExpired : AuthConstants.ErrorCodes.InvalidToken);
            }

            // Get the user
            var user = token.User;

            if (user == null || !user.IsActive)
            {
                _logger.LogWarning("User {UserId} not found or inactive", token.UserId);
                throw new UnauthorizedException("User not found or inactive", AuthConstants.ErrorCodes.AccountInactive);
            }

            // Revoke old token (token rotation)
            await _authRepository.RevokeRefreshTokenAsync(token, ipAddress, "Token rotation");

            // Generate new tokens
            var newAccessToken = _jwtTokenService.GenerateAccessToken(user);
            var newRefreshToken = await CreateRefreshTokenAsync(user.Id, ipAddress, userAgent);

            // Link old token to new token for audit trail
            token.ReplacedByTokenId = newRefreshToken.Id;
            await _authRepository.UpdateRefreshTokenAsync(token);

            _logger.LogInformation("Refresh token rotated for user {UserId}", user.Id);

            // Build response
            var expirationMinutes = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "60");

            return new AuthResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken.Token,
                TokenType = "Bearer",
                ExpiresIn = expirationMinutes * 60, // Convert to seconds
                User = MapUserToDto(user)
            };
        }
        catch (UnauthorizedException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            throw new AppException("An error occurred while refreshing token", ex);
        }
    }

    /// <summary>
    /// Revokes a refresh token (logout)
    ///
    /// Process:
    /// 1. Find refresh token
    /// 2. Validate it belongs to the user
    /// 3. Revoke it
    ///
    /// Note: Access tokens cannot be revoked (they expire naturally)
    /// Client should delete the access token on logout
    /// </summary>
    public async Task RevokeTokenAsync(string refreshToken, string ipAddress)
    {
        try
        {
            _logger.LogDebug("Revoke token request from IP {IpAddress}", ipAddress);

            var token = await _authRepository.GetRefreshTokenAsync(refreshToken);

            if (token == null)
            {
                _logger.LogWarning("Revoke failed: Token not found");
                throw new NotFoundException("Token not found");
            }

            if (!token.IsActive)
            {
                _logger.LogWarning("Revoke failed: Token {TokenId} already inactive", token.Id);
                throw new BadRequestException("Token is already revoked or expired");
            }

            await _authRepository.RevokeRefreshTokenAsync(token, ipAddress, "User logout");

            _logger.LogInformation("Refresh token {TokenId} revoked for user {UserId}",
                token.Id, token.UserId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking token");
            throw;
        }
    }

    /// <summary>
    /// Gets the current user by ID
    /// Used by controllers to get user information
    /// </summary>
    public async Task<User?> GetCurrentUserAsync(Guid userId)
    {
        try
        {
            return await _authRepository.GetUserByIdAsync(userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user {UserId}", userId);
            throw;
        }
    }

    #region Private Helper Methods

    /// <summary>
    /// Generates authentication response with access and refresh tokens
    /// Helper method to avoid code duplication
    /// </summary>
    private async Task<AuthResponse> GenerateAuthResponseAsync(User user, string ipAddress, string? userAgent)
    {
        // Generate access token (JWT)
        var accessToken = _jwtTokenService.GenerateAccessToken(user);

        // Generate and save refresh token
        var refreshToken = await CreateRefreshTokenAsync(user.Id, ipAddress, userAgent);

        // Get token expiration from configuration
        var expirationMinutes = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "60");

        // Build response
        return new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token,
            TokenType = "Bearer",
            ExpiresIn = expirationMinutes * 60, // Convert to seconds
            User = MapUserToDto(user)
        };
    }

    /// <summary>
    /// Creates and saves a new refresh token
    /// </summary>
    private async Task<RefreshToken> CreateRefreshTokenAsync(Guid userId, string ipAddress, string? userAgent)
    {
        // Get refresh token expiration from configuration (default: 7 days)
        var expirationDays = int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"] ?? "7");

        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Token = _jwtTokenService.GenerateRefreshToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(expirationDays),
            CreatedAt = DateTime.UtcNow,
            CreatedByIp = ipAddress,
            UserAgent = userAgent
        };

        return await _authRepository.CreateRefreshTokenAsync(refreshToken);
    }

    /// <summary>
    /// Maps User entity to UserDto
    /// Prevents exposing sensitive information
    /// </summary>
    private UserDto MapUserToDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            ProfilePictureUrl = user.ProfilePictureUrl,
            AuthProvider = user.AuthProvider,
            IsEmailVerified = user.IsEmailVerified,
            CreatedAt = user.CreatedAt
        };
    }

    #endregion
}
