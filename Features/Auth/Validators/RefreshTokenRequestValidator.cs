using FitnessApp.Api.Features.Auth.DTOs;
using FluentValidation;

namespace FitnessApp.Api.Features.Auth.Validators;

/// <summary>
/// Validator for RefreshTokenRequest
/// </summary>
public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
{
    public RefreshTokenRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty()
            .WithMessage("Refresh token is required")
            .MinimumLength(10)
            .WithMessage("Invalid refresh token format");
    }
}
