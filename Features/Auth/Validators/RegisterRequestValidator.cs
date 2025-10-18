using FitnessApp.Api.Features.Auth.DTOs;
using FitnessApp.Api.Shared.Constants;
using FluentValidation;

namespace FitnessApp.Api.Features.Auth.Validators;

/// <summary>
/// Validator for RegisterRequest
/// Uses FluentValidation for comprehensive validation rules
/// </summary>
public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        // Email validation
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage(AuthConstants.ValidationMessages.EmailRequired)
            .EmailAddress()
            .WithMessage(AuthConstants.ValidationMessages.EmailInvalid)
            .MaximumLength(AppConstants.Validation.MaxEmailLength)
            .WithMessage($"Email cannot exceed {AppConstants.Validation.MaxEmailLength} characters");

        // Password validation
        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage(AuthConstants.ValidationMessages.PasswordRequired)
            .MinimumLength(AppConstants.Validation.MinPasswordLength)
            .WithMessage(AuthConstants.ValidationMessages.PasswordMinLength)
            .MaximumLength(AppConstants.Validation.MaxPasswordLength)
            .WithMessage($"Password cannot exceed {AppConstants.Validation.MaxPasswordLength} characters")
            .Matches(@"[A-Z]")
            .WithMessage("Password must contain at least one uppercase letter")
            .Matches(@"[a-z]")
            .WithMessage("Password must contain at least one lowercase letter")
            .Matches(@"[0-9]")
            .WithMessage("Password must contain at least one number")
            .Matches(@"[\W_]")
            .WithMessage("Password must contain at least one special character");

        // Confirm password validation
        RuleFor(x => x.ConfirmPassword)
            .NotEmpty()
            .WithMessage("Password confirmation is required")
            .Equal(x => x.Password)
            .WithMessage(AuthConstants.ValidationMessages.PasswordsDoNotMatch);

        // Optional fields validation
        RuleFor(x => x.FirstName)
            .MaximumLength(AppConstants.Validation.MaxNameLength)
            .WithMessage($"First name cannot exceed {AppConstants.Validation.MaxNameLength} characters")
            .When(x => !string.IsNullOrEmpty(x.FirstName));

        RuleFor(x => x.LastName)
            .MaximumLength(AppConstants.Validation.MaxNameLength)
            .WithMessage($"Last name cannot exceed {AppConstants.Validation.MaxNameLength} characters")
            .When(x => !string.IsNullOrEmpty(x.LastName));
    }
}
