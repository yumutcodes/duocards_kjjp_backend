using System.Text;

using FitnessApp.Api.Features.Auth;
using FitnessApp.Api.Infrastructure.Data;
using FitnessApp.Api.Infrastructure.Repositories;
using FitnessApp.Api.Infrastructure.Services;
using FitnessApp.Api.Shared.Extensions;
using FitnessApp.Api.Shared.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// SERVICE CONFIGURATION
// ============================================================================

// Add controllers
builder.Services.AddControllers();

// Add FluentValidation
builder.Services.AddFluentValidators();

// Configure CORS (Cross-Origin Resource Sharing)
// Allows frontend applications from different domains to access the API
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()     // Allow requests from any origin (configure for production)
              .AllowAnyMethod()     // Allow any HTTP method (GET, POST, etc.)
              .AllowAnyHeader();    // Allow any headers
    });

    // Production configuration example (more restrictive):
    // options.AddPolicy("Production", policy =>
    // {
    //     policy.WithOrigins("https://yourfrontend.com")
    //           .AllowAnyMethod()
    //           .AllowAnyHeader()
    //           .AllowCredentials();
    // });
});

// Configure Database (MySQL with Pomelo)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Use MySQL 8.0 as the server version (change if using different version)
    var serverVersion = new MySqlServerVersion(new Version(8, 0, 35));

    options.UseMySql(connectionString, serverVersion,
        mySqlOptions =>
        {
            // Enable retry on transient failures
            mySqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(30),
                errorNumbersToAdd: null);

            // Optional: Set command timeout
            mySqlOptions.CommandTimeout(30);
        });

    // Enable sensitive data logging in development (shows parameter values in logs)
    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
        options.EnableDetailedErrors();
    }
});

// Configure JWT Authentication
var jwtSettings = builder.Configuration.GetSection("Jwt");
var secretKey = jwtSettings["SecretKey"]
    ?? throw new InvalidOperationException("JWT Secret Key is not configured");

builder.Services.AddAuthentication(options =>
{
    // Set JWT as the default authentication scheme
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment(); // Require HTTPS in production

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero // No tolerance for token expiration
    };

    // Configure events for additional logging/handling
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Authentication failed: {Message}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogDebug("Token validated for user: {UserId}",
                context.Principal?.FindFirst("sub")?.Value);
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Authentication challenge: {Error} - {ErrorDescription}",
                context.Error, context.ErrorDescription);
            return Task.CompletedTask;
        }
    };
});

// Configure Authorization
builder.Services.AddAuthorization();

// Register application services (Dependency Injection)
// Scoped: Created once per request
builder.Services.AddScoped<IAuthRepository, AuthRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();

// Singleton: Created once for the application lifetime (thread-safe services)
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
builder.Services.AddSingleton<IPasswordHashingService, PasswordHashingService>();
builder.Services.AddSingleton<IGoogleOAuthService, GoogleOAuthService>();

// Configure Swagger/OpenAPI for API documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Fitness App API",
        Version = "v1",
        Description = "Authentication API for Fitness Application with Email/Password and Google OAuth support",
        Contact = new OpenApiContact
        {
            Name = "Fitness App Team",
            Email = "support@fitnessapp.com"
        }
    });

    // Add JWT authentication to Swagger UI
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token in the format: {your token}"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Include XML comments if available (for detailed API documentation)
    // var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    // var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    // if (File.Exists(xmlPath))
    // {
    //     options.IncludeXmlComments(xmlPath);
    // }
});

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// Set minimum log level based on environment
if (builder.Environment.IsDevelopment())
{
    builder.Logging.SetMinimumLevel(LogLevel.Debug);
}
else
{
    builder.Logging.SetMinimumLevel(LogLevel.Information);
}

var app = builder.Build();

// ============================================================================
// MIDDLEWARE PIPELINE CONFIGURATION
// Order matters! Middleware is executed in the order it's added.
// ============================================================================

// Enable Swagger in development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "Fitness App API v1");
        options.RoutePrefix = string.Empty; // Swagger UI at root URL (http://localhost:5000)
    });
}

// Global exception handling - Must be first in the pipeline
app.UseExceptionHandlingMiddleware();

// HTTPS Redirection (redirect HTTP to HTTPS)
// Disabled in development for easier testing
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// CORS - Must be before authentication/authorization
app.UseCors("AllowAll"); // Use "Production" policy in production

// Authentication - Must be before authorization
app.UseAuthentication();

// Authorization - Must be after authentication
app.UseAuthorization();

// Map controllers
app.MapControllers();

// ============================================================================
// DATABASE MIGRATION (Optional - Auto-migrate on startup)
// Comment out in production and use manual migrations instead
// ============================================================================
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        // Check if database can be connected to
        logger.LogInformation("Checking database connection...");
        await dbContext.Database.CanConnectAsync();
        logger.LogInformation("Database connection successful");

        // Apply pending migrations
        logger.LogInformation("Applying database migrations...");
        await dbContext.Database.MigrateAsync();
        logger.LogInformation("Database migrations applied successfully");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred while migrating the database");
        // Don't throw - let the application start even if DB migration fails
    }
}

// ============================================================================
// START THE APPLICATION
// ============================================================================
app.Run();

// Make the Program class accessible to integration tests
public partial class Program { }
