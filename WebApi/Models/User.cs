namespace WebApi.Models;

/// <summary>
/// User entity for authentication
/// 
/// Security Notes:
/// - In production, NEVER store plain-text passwords
/// - Use ASP.NET Identity or a password hasher (BCrypt, Argon2)
/// - Consider adding: PasswordHash, PasswordSalt, EmailConfirmed, LockoutEnabled, etc.
/// </summary>
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    
    // WARNING: This should be a hashed password in production
    // Example with BCrypt: public string PasswordHash { get; set; }
    public string Password { get; set; } = string.Empty;
    
    public string Email { get; set; } = string.Empty;
    
    // Role for authorization (e.g., "Admin", "User", "Manager")
    // For complex scenarios, consider a separate Roles table with many-to-many relationship
    public string Role { get; set; } = "User";
}
