using System.Security.Claims;
using FitnessApp.Api.Features.Auth.DTOs;
using FitnessApp.Api.Shared.Exceptions;
using FitnessApp.Api.Shared.Extensions;
using FitnessApp.Api.Shared.Models;
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
    [ProducesResponseType(typeof(ApiResponse<AuthResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Get IP address and user agent for security tracking
        var ipAddress = HttpContext.GetIpAddress();
        var userAgent = HttpContext.GetUserAgent();

        // Register user
        var response = await _authService.RegisterAsync(request, ipAddress, userAgent);

        _logger.LogInformation("User registered successfully: {Email}", request.Email);

        return Ok(ApiResponse<AuthResponse>.SuccessResult(response, "User registered successfully"));
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
    [ProducesResponseType(typeof(ApiResponse<AuthResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ipAddress = HttpContext.GetIpAddress();
        var userAgent = HttpContext.GetUserAgent();

        var response = await _authService.LoginAsync(request, ipAddress, userAgent);

        _logger.LogInformation("User logged in successfully: {Email}", request.Email);

        return Ok(ApiResponse<AuthResponse>.SuccessResult(response, "Login successful"));
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
    [ProducesResponseType(typeof(ApiResponse<AuthResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
    {
        var ipAddress = HttpContext.GetIpAddress();
        var userAgent = HttpContext.GetUserAgent();

        var response = await _authService.GoogleLoginAsync(request, ipAddress, userAgent);

        _logger.LogInformation("User logged in successfully via Google");

        return Ok(ApiResponse<AuthResponse>.SuccessResult(response, "Google login successful"));
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
    [ProducesResponseType(typeof(ApiResponse<AuthResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var ipAddress = HttpContext.GetIpAddress();
        var userAgent = HttpContext.GetUserAgent();

        var response = await _authService.RefreshTokenAsync(request.RefreshToken, ipAddress, userAgent);

        _logger.LogInformation("Token refreshed successfully");

        return Ok(ApiResponse<AuthResponse>.SuccessResult(response, "Token refreshed successfully"));
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
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
    {
        var ipAddress = HttpContext.GetIpAddress();

        await _authService.RevokeTokenAsync(request.RefreshToken, ipAddress);

        _logger.LogInformation("Token revoked successfully");

        return Ok(ApiResponse.SuccessResult("Token revoked successfully"));
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
    [ProducesResponseType(typeof(ApiResponse<UserDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetCurrentUser()
    {
        // Get user ID from JWT claims using extension method
        var userId = HttpContext.GetUserId();

        if (!userId.HasValue)
        {
            _logger.LogWarning("Invalid user ID claim in token");
            throw new UnauthorizedException("User ID not found in token");
        }

        var user = await _authService.GetCurrentUserAsync(userId.Value);

        if (user == null)
        {
            _logger.LogWarning("User {UserId} not found", userId);
            throw new NotFoundException("User not found");
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

        return Ok(ApiResponse<UserDto>.SuccessResult(userDto, "User information retrieved successfully"));
    }
}
