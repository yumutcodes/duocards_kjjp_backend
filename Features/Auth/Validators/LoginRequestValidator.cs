using FitnessApp.Api.Features.Auth.DTOs;
using FitnessApp.Api.Shared.Constants;
using FluentValidation;

namespace FitnessApp.Api.Features.Auth.Validators;

/// <summary>
/// Validator for LoginRequest
/// </summary>
public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage(AuthConstants.ValidationMessages.EmailRequired)
            .EmailAddress()
            .WithMessage(AuthConstants.ValidationMessages.EmailInvalid);

        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage(AuthConstants.ValidationMessages.PasswordRequired);
    }
}
