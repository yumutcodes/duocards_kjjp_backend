using System.Security.Claims;
using FitnessApp.Api.Features.Auth.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FitnessApp.Api.Features.Auth;

/// <summary>
/// API Controller for authentication endpoints
/// Handles user registration, login, token refresh, and logout
///
/// All endpoints return standardized responses:
/// - 200 OK: Successful operation
/// - 400 Bad Request: Validation errors
/// - 401 Unauthorized: Authentication failed
/// - 500 Internal Server Error: Unexpected errors
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    /// <summary>
    /// Register a new user with email and password
    /// </summary>
    /// <param name="request">Registration details</param>
    /// <returns>Authentication response with tokens</returns>
    /// <response code="200">User registered successfully</response>
    /// <response code="400">Validation errors or email already exists</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("register")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            // Validate model state (automatic from data annotations)
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Get IP address and user agent for security tracking
            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();

            // Register user
            var response = await _authService.RegisterAsync(request, ipAddress, userAgent);

            _logger.LogInformation("User registered successfully: {Email}", request.Email);

            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            // Business logic errors (e.g., email already exists)
            _logger.LogWarning(ex, "Registration failed for {Email}: {Message}", request.Email, ex.Message);
            return BadRequest(new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Registration Failed",
                Detail = ex.Message
            });
        }
        catch (Exception ex)
        {
            // Unexpected errors
            _logger.LogError(ex, "Unexpected error during registration for {Email}", request.Email);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred during registration"
            });
        }
    }

    /// <summary>
    /// Login with email and password
    /// </summary>
    /// <param name="request">Login credentials</param>
    /// <returns>Authentication response with tokens</returns>
    /// <response code="200">Login successful</response>
    /// <response code="400">Validation errors</response>
    /// <response code="401">Invalid credentials</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();

            var response = await _authService.LoginAsync(request, ipAddress, userAgent);

            _logger.LogInformation("User logged in successfully: {Email}", request.Email);

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            // Authentication failures
            _logger.LogWarning(ex, "Login failed for {Email}: {Message}", request.Email, ex.Message);
            return Unauthorized(new ProblemDetails
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Login Failed",
                Detail = ex.Message
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for {Email}", request.Email);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred during login"
            });
        }
    }

    /// <summary>
    /// Login or register with Google OAuth
    /// </summary>
    /// <param name="request">Google ID token</param>
    /// <returns>Authentication response with tokens</returns>
    /// <response code="200">Google login successful</response>
    /// <response code="400">Validation errors</response>
    /// <response code="401">Invalid Google token</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("google")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();

            var response = await _authService.GoogleLoginAsync(request, ipAddress, userAgent);

            _logger.LogInformation("User logged in successfully via Google");

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Google login failed: {Message}", ex.Message);
            return Unauthorized(new ProblemDetails
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Google Login Failed",
                Detail = ex.Message
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during Google login");
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred during Google login"
            });
        }
    }

    /// <summary>
    /// Refresh access token using refresh token
    /// Implements token rotation for security
    /// </summary>
    /// <param name="request">Refresh token</param>
    /// <returns>New authentication response with tokens</returns>
    /// <response code="200">Token refreshed successfully</response>
    /// <response code="400">Validation errors</response>
    /// <response code="401">Invalid or expired refresh token</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();

            var response = await _authService.RefreshTokenAsync(request.RefreshToken, ipAddress, userAgent);

            _logger.LogInformation("Token refreshed successfully");

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Token refresh failed: {Message}", ex.Message);
            return Unauthorized(new ProblemDetails
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Token Refresh Failed",
                Detail = ex.Message
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token refresh");
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred during token refresh"
            });
        }
    }

    /// <summary>
    /// Revoke refresh token (logout)
    /// Client should also delete access token
    /// </summary>
    /// <param name="request">Refresh token to revoke</param>
    /// <returns>Success message</returns>
    /// <response code="200">Token revoked successfully</response>
    /// <response code="400">Validation errors or token not found</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("revoke")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = GetIpAddress();

            await _authService.RevokeTokenAsync(request.RefreshToken, ipAddress);

            _logger.LogInformation("Token revoked successfully");

            return Ok(new { message = "Token revoked successfully" });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Token revocation failed: {Message}", ex.Message);
            return BadRequest(new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Token Revocation Failed",
                Detail = ex.Message
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token revocation");
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred during token revocation"
            });
        }
    }

    /// <summary>
    /// Get current authenticated user's information
    /// Requires valid access token in Authorization header
    /// </summary>
    /// <returns>User information</returns>
    /// <response code="200">User information retrieved successfully</response>
    /// <response code="401">Not authenticated</response>
    /// <response code="404">User not found</response>
    /// <response code="500">Internal server error</response>
    [HttpGet("me")]
    [Authorize] // Requires authentication
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetCurrentUser()
    {
        try
        {
            // Get user ID from JWT claims
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? User.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                _logger.LogWarning("Invalid user ID claim in token");
                return Unauthorized(new ProblemDetails
                {
                    Status = StatusCodes.Status401Unauthorized,
                    Title = "Invalid Token",
                    Detail = "User ID not found in token"
                });
            }

            var user = await _authService.GetCurrentUserAsync(userId);

            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found", userId);
                return NotFound(new ProblemDetails
                {
                    Status = StatusCodes.Status404NotFound,
                    Title = "User Not Found",
                    Detail = "The requested user was not found"
                });
            }

            var userDto = new UserDto
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

            return Ok(userDto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error getting current user");
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred"
            });
        }
    }

    #region Helper Methods

    /// <summary>
    /// Gets the client's IP address from the request
    /// Handles X-Forwarded-For header for reverse proxy scenarios
    /// </summary>
    private string GetIpAddress()
    {
        // Check for X-Forwarded-For header (set by reverse proxies/load balancers)
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
        {
            var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                // X-Forwarded-For can contain multiple IPs, take the first one
                return forwardedFor.Split(',')[0].Trim();
            }
        }

        // Fallback to RemoteIpAddress
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    /// <summary>
    /// Gets the client's user agent string
    /// Useful for identifying the device/browser
    /// </summary>
    private string? GetUserAgent()
    {
        return Request.Headers["User-Agent"].FirstOrDefault();
    }

    #endregion
}
