using FitnessApp.Api.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace FitnessApp.Api.Infrastructure.Data;

/// <summary>
/// Entity Framework Core database context for the Fitness Application.
/// Manages database connections and entity configurations.
/// </summary>
public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// DbSet for User entities
    /// </summary>
    public DbSet<User> Users => Set<User>();

    /// <summary>
    /// DbSet for RefreshToken entities
    /// </summary>
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    /// <summary>
    /// Configure entity relationships and constraints
    /// </summary>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure User entity
        modelBuilder.Entity<User>(entity =>
        {
            // Set table name
            entity.ToTable("users");

            // Primary key
            entity.HasKey(e => e.Id);

            // Unique constraint on email
            entity.HasIndex(e => e.Email)
                .IsUnique()
                .HasDatabaseName("idx_users_email");

            // Index on provider user id for faster OAuth lookups
            entity.HasIndex(e => new { e.AuthProvider, e.ProviderUserId })
                .HasDatabaseName("idx_users_provider");

            // Index on created_at for sorting
            entity.HasIndex(e => e.CreatedAt)
                .HasDatabaseName("idx_users_created_at");

            // Configure relationships
            entity.HasMany(e => e.RefreshTokens)
                .WithOne(e => e.User)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade); // Delete all refresh tokens when user is deleted

            // Property configurations
            entity.Property(e => e.Email)
                .IsRequired()
                .HasMaxLength(255);

            entity.Property(e => e.PasswordHash)
                .HasMaxLength(255);

            entity.Property(e => e.FirstName)
                .HasMaxLength(100);

            entity.Property(e => e.LastName)
                .HasMaxLength(100);

            entity.Property(e => e.ProfilePictureUrl)
                .HasMaxLength(500);

            entity.Property(e => e.AuthProvider)
                .IsRequired()
                .HasMaxLength(50)
                .HasDefaultValue("Email");

            entity.Property(e => e.ProviderUserId)
                .HasMaxLength(255);

            entity.Property(e => e.IsEmailVerified)
                .HasDefaultValue(false);

            entity.Property(e => e.IsActive)
                .HasDefaultValue(true);

            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)");

            entity.Property(e => e.UpdatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)");
        });

        // Configure RefreshToken entity
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            // Set table name
            entity.ToTable("refresh_tokens");

            // Primary key
            entity.HasKey(e => e.Id);

            // Index on user_id for faster lookups
            entity.HasIndex(e => e.UserId)
                .HasDatabaseName("idx_refresh_tokens_user_id");

            // Unique index on token for security
            entity.HasIndex(e => e.Token)
                .IsUnique()
                .HasDatabaseName("idx_refresh_tokens_token");

            // Index on expires_at for cleanup queries
            entity.HasIndex(e => e.ExpiresAt)
                .HasDatabaseName("idx_refresh_tokens_expires_at");

            // Property configurations
            entity.Property(e => e.Token)
                .IsRequired()
                .HasMaxLength(500);

            entity.Property(e => e.ExpiresAt)
                .IsRequired();

            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)");

            entity.Property(e => e.CreatedByIp)
                .HasMaxLength(50);

            entity.Property(e => e.RevokedByIp)
                .HasMaxLength(50);

            entity.Property(e => e.RevokeReason)
                .HasMaxLength(200);

            entity.Property(e => e.UserAgent)
                .HasMaxLength(500);
        });
    }

    /// <summary>
    /// Override SaveChanges to automatically update UpdatedAt timestamp
    /// </summary>
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }

    /// <summary>
    /// Override SaveChangesAsync to automatically update UpdatedAt timestamp
    /// </summary>
    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return base.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Automatically update UpdatedAt timestamp for modified entities
    /// </summary>
    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e.Entity is User && e.State == EntityState.Modified);

        foreach (var entry in entries)
        {
            if (entry.Entity is User user)
            {
                user.UpdatedAt = DateTime.UtcNow;
            }
        }
    }
}
