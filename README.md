# Fitness App - Authentication API

A comprehensive authentication backend built with ASP.NET Core 8.0, featuring:
- Email/Password authentication with BCrypt password hashing
- Google OAuth 2.0 integration
- JWT token-based authentication
- Refresh token rotation for enhanced security
- MySQL database with Entity Framework Core

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [Configuration](#configuration)
- [Database Migration](#database-migration)
- [API Endpoints](#api-endpoints)
- [Security Features](#security-features)
- [Project Structure](#project-structure)
- [Testing](#testing)

## Features

### Authentication Methods
- **Email/Password Registration & Login**
  - Secure password hashing with BCrypt (work factor: 12)
  - Email validation
  - Password strength requirements

- **Google OAuth 2.0**
  - Sign in with Google
  - Automatic account creation
  - Profile information sync

### Security Features
- JWT access tokens (short-lived, 60 minutes)
- Refresh tokens (long-lived, 7 days)
- Token rotation on refresh (prevents replay attacks)
- IP address and user agent tracking
- HTTPS enforcement in production
- CORS configuration
- Comprehensive logging and auditing

### Data Management
- MySQL database with Entity Framework Core
- Automatic migrations in development
- Comprehensive entity relationships
- Optimized database indexes

## Architecture

The project follows Clean Architecture principles:

```
FitnessApp.Api/
├── Core/
│   └── Entities/          # Domain entities (User, RefreshToken)
├── Infrastructure/
│   ├── Data/              # Database context
│   ├── Repositories/      # Data access layer
│   └── Services/          # Infrastructure services (JWT, Password, OAuth)
├── Features/
│   └── Auth/              # Authentication feature
│       ├── DTOs/          # Data transfer objects
│       ├── AuthService.cs # Business logic
│       └── AuthController.cs # API endpoints
└── Program.cs             # Application configuration
```

## Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [MySQL Server 8.0+](https://dev.mysql.com/downloads/mysql/)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)
- [Postman](https://www.postman.com/) or similar API testing tool (optional)

## Setup Instructions

### 1. Clone the Repository
```bash
cd C:\Users\umutf\dot.netProjects\fitnessAppBackend\FitnessApp.Api
```

### 2. Install Dependencies
```bash
dotnet restore
```

### 3. Configure Database Connection

Edit `appsettings.json` and update the MySQL connection string:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Port=3306;Database=fitnessapp;User=root;Password=YOUR_MYSQL_PASSWORD;"
  }
}
```

### 4. Configure JWT Secret

**IMPORTANT**: Change the JWT secret key in `appsettings.json`:

```json
{
  "Jwt": {
    "SecretKey": "YOUR_SECURE_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG"
  }
}
```

**Production**: Use environment variables or Azure Key Vault instead of storing secrets in appsettings.json

### 5. Configure Google OAuth (Optional)

To enable Google Sign-In:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials (Web application)
5. Add authorized redirect URIs
6. Copy the Client ID to `appsettings.json`:

```json
{
  "Authentication": {
    "Google": {
      "ClientId": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
    }
  }
}
```

### 6. Create Database Migration

```bash
# Install EF Core tools (if not already installed)
dotnet tool install --global dotnet-ef

# Create initial migration
dotnet ef migrations add InitialCreate

# Apply migration to database
dotnet ef database update
```

**Note**: In development mode, migrations are applied automatically on startup (see Program.cs)

### 7. Run the Application

```bash
dotnet run
```

The API will start at:
- HTTP: `http://localhost:5000`
- HTTPS: `https://localhost:5001`
- Swagger UI: `http://localhost:5000` or `https://localhost:5001`

## Configuration

### appsettings.json Structure

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "MySQL connection string"
  },
  "Jwt": {
    "SecretKey": "Secret key for signing JWT tokens (min 32 chars)",
    "Issuer": "Token issuer (your API name)",
    "Audience": "Token audience (your client app)",
    "AccessTokenExpirationMinutes": "60",
    "RefreshTokenExpirationDays": "7"
  },
  "Authentication": {
    "Google": {
      "ClientId": "Google OAuth Client ID"
    }
  }
}
```

### Environment-Specific Configuration

Create `appsettings.Development.json` for development settings (already exists).

For production, create `appsettings.Production.json` or use environment variables:

```bash
# Windows
set Jwt__SecretKey=your_secret_key
set ConnectionStrings__DefaultConnection=your_connection_string

# Linux/Mac
export Jwt__SecretKey=your_secret_key
export ConnectionStrings__DefaultConnection=your_connection_string
```

## Database Migration

### Creating Migrations

```bash
# Create a new migration
dotnet ef migrations add MigrationName

# View migration SQL
dotnet ef migrations script

# List all migrations
dotnet ef migrations list
```

### Applying Migrations

```bash
# Apply all pending migrations
dotnet ef database update

# Revert to specific migration
dotnet ef database update MigrationName

# Remove last migration (if not applied)
dotnet ef migrations remove
```

### Database Schema

**users table**:
- `id` (GUID): Primary key
- `email` (VARCHAR): Unique, indexed
- `password_hash` (VARCHAR): BCrypt hash
- `first_name`, `last_name` (VARCHAR)
- `profile_picture_url` (VARCHAR)
- `auth_provider` (VARCHAR): "Email" or "Google"
- `provider_user_id` (VARCHAR): Google user ID
- `is_email_verified` (BOOLEAN)
- `is_active` (BOOLEAN)
- `created_at`, `updated_at`, `last_login_at` (DATETIME)

**refresh_tokens table**:
- `id` (GUID): Primary key
- `user_id` (GUID): Foreign key to users
- `token` (VARCHAR): Unique, indexed
- `expires_at` (DATETIME): Token expiration
- `created_at`, `created_by_ip`, `user_agent`
- `revoked_at`, `revoked_by_ip`, `revoke_reason`
- `replaced_by_token_id` (GUID): For token rotation

## API Endpoints

### Authentication Endpoints

#### POST /api/auth/register
Register a new user with email and password.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "long_random_string...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "user": {
    "id": "guid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "profilePictureUrl": null,
    "authProvider": "Email",
    "isEmailVerified": false,
    "createdAt": "2024-01-01T00:00:00Z"
  }
}
```

#### POST /api/auth/login
Login with email and password.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response**: Same as registration

#### POST /api/auth/google
Login or register with Google OAuth.

**Request Body**:
```json
{
  "idToken": "google_id_token_from_client"
}
```

**Response**: Same as registration/login

**Client-side implementation** (React example):
```javascript
// Use Google Sign-In SDK to get ID token
const response = await gapi.auth2.getAuthInstance().signIn();
const idToken = response.getAuthResponse().id_token;

// Send to backend
await fetch('/api/auth/google', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ idToken })
});
```

#### POST /api/auth/refresh
Refresh access token using refresh token.

**Request Body**:
```json
{
  "refreshToken": "your_refresh_token"
}
```

**Response**: Same as login (with new tokens)

#### POST /api/auth/revoke
Revoke refresh token (logout).

**Request Body**:
```json
{
  "refreshToken": "your_refresh_token"
}
```

**Response** (200 OK):
```json
{
  "message": "Token revoked successfully"
}
```

#### GET /api/auth/me
Get current user information (requires authentication).

**Headers**:
```
Authorization: Bearer {access_token}
```

**Response** (200 OK):
```json
{
  "id": "guid",
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "profilePictureUrl": null,
  "authProvider": "Email",
  "isEmailVerified": false,
  "createdAt": "2024-01-01T00:00:00Z"
}
```

## Security Features

### Password Security
- **BCrypt hashing**: Industry-standard password hashing
- **Work factor 12**: ~250ms to hash (resistant to brute force)
- **Automatic salt generation**: Each password gets unique salt
- **Constant-time comparison**: Prevents timing attacks

### JWT Security
- **Short-lived access tokens**: 60 minutes expiration
- **Secure signing**: HMAC-SHA256 algorithm
- **Claims-based**: User ID, email, auth provider
- **Issuer/Audience validation**: Prevents token misuse

### Refresh Token Security
- **Token rotation**: Old token invalidated on refresh
- **Long expiration**: 7 days (configurable)
- **Cryptographically secure**: 64 bytes random data
- **IP and user agent tracking**: Security auditing
- **Revocation support**: Manual logout
- **One-time use**: Reuse detection

### API Security
- **CORS configuration**: Control allowed origins
- **HTTPS enforcement**: Production mode
- **Rate limiting**: (Add middleware for production)
- **Input validation**: Data annotations
- **SQL injection prevention**: Parameterized queries (EF Core)
- **Logging**: Comprehensive audit trail

## Project Structure

```
FitnessApp.Api/
│
├── Core/                           # Domain layer
│   └── Entities/
│       ├── User.cs                 # User entity with auth providers
│       └── RefreshToken.cs         # Refresh token entity
│
├── Infrastructure/                 # Infrastructure layer
│   ├── Data/
│   │   └── ApplicationDbContext.cs # EF Core context
│   │
│   ├── Repositories/
│   │   └── AuthRepository.cs       # Data access for auth
│   │
│   └── Services/
│       ├── JwtTokenService.cs      # JWT generation/validation
│       ├── PasswordHashingService.cs # BCrypt password hashing
│       └── GoogleOAuthService.cs   # Google token verification
│
├── Features/                       # Feature-based organization
│   └── Auth/
│       ├── DTOs/                   # Data transfer objects
│       │   ├── RegisterRequest.cs
│       │   ├── LoginRequest.cs
│       │   ├── GoogleLoginRequest.cs
│       │   ├── RefreshTokenRequest.cs
│       │   ├── RevokeTokenRequest.cs
│       │   └── AuthResponse.cs
│       │
│       ├── AuthService.cs          # Business logic
│       └── AuthController.cs       # API endpoints
│
├── Migrations/                     # EF Core migrations
│
├── Program.cs                      # Application startup
├── appsettings.json               # Configuration
└── FitnessApp.Api.csproj          # Project file
```

## Testing

### Manual Testing with Swagger

1. Run the application: `dotnet run`
2. Open browser: `http://localhost:5000`
3. Use Swagger UI to test endpoints

### Testing with Postman

Import these requests:

**1. Register**
```
POST http://localhost:5000/api/auth/register
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "Test123!@#",
  "confirmPassword": "Test123!@#",
  "firstName": "Test",
  "lastName": "User"
}
```

**2. Login**
```
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "Test123!@#"
}
```

**3. Get Current User**
```
GET http://localhost:5000/api/auth/me
Authorization: Bearer {access_token}
```

**4. Refresh Token**
```
POST http://localhost:5000/api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "{your_refresh_token}"
}
```

**5. Logout**
```
POST http://localhost:5000/api/auth/revoke
Content-Type: application/json

{
  "refreshToken": "{your_refresh_token}"
}
```

### Unit Testing

Create test project:
```bash
dotnet new xunit -n FitnessApp.Api.Tests
cd FitnessApp.Api.Tests
dotnet add reference ../FitnessApp.Api/FitnessApp.Api.csproj
dotnet add package Moq
dotnet add package Microsoft.EntityFrameworkCore.InMemory
```

## Production Deployment

### Pre-deployment Checklist

- [ ] Change JWT secret key (use environment variable)
- [ ] Update MySQL connection string (use environment variable)
- [ ] Configure Google OAuth Client ID
- [ ] Enable HTTPS redirection
- [ ] Configure CORS for specific origins
- [ ] Set up logging (Application Insights, Serilog, etc.)
- [ ] Enable rate limiting
- [ ] Set up health checks
- [ ] Configure reverse proxy (nginx, IIS)
- [ ] Set up automated backups for database
- [ ] Review and adjust token expiration times
- [ ] Enable database connection pooling
- [ ] Set up monitoring and alerts

### Environment Variables

```bash
# Required
export ConnectionStrings__DefaultConnection="Server=..."
export Jwt__SecretKey="..."
export Authentication__Google__ClientId="..."

# Optional
export ASPNETCORE_ENVIRONMENT="Production"
export ASPNETCORE_URLS="http://+:80"
```

### Docker Deployment (Example)

```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY . .
RUN dotnet restore
RUN dotnet publish -c Release -o out

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .
ENTRYPOINT ["dotnet", "FitnessApp.Api.dll"]
```

## Troubleshooting

### Common Issues

**MySQL Connection Failed**
- Check MySQL is running: `mysql -u root -p`
- Verify connection string
- Check firewall settings

**JWT Token Invalid**
- Verify secret key matches between config and token
- Check token expiration
- Ensure clock sync (token validation is time-sensitive)

**Google OAuth Failed**
- Verify Client ID is correct
- Check ID token format
- Ensure Google+ API is enabled

**Migration Failed**
- Check database permissions
- Verify connection string
- Review migration SQL: `dotnet ef migrations script`

## License

This project is private and proprietary.

## Support

For issues and questions, contact: support@fitnessapp.com
