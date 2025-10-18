using FitnessApp.Api.Features.Auth.DTOs;
using FluentValidation;

namespace FitnessApp.Api.Features.Auth.Validators;

/// <summary>
/// Validator for GoogleLoginRequest
/// </summary>
public class GoogleLoginRequestValidator : AbstractValidator<GoogleLoginRequest>
{
    public GoogleLoginRequestValidator()
    {
        RuleFor(x => x.IdToken)
            .NotEmpty()
            .WithMessage("Google ID token is required")
            .MinimumLength(10)
            .WithMessage("Invalid Google ID token format");
    }
}
