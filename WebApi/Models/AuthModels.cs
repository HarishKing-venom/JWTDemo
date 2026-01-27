namespace WebApi.Models;

/// <summary>
/// Request model for user login
/// Sent as JSON in the request body to POST /api/auth/login
/// </summary>
public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Response model returned after successful authentication
/// Contains the JWT token and metadata
/// </summary>
public class LoginResponse
{
    // The JWT token string - client should store this securely
    // Options: localStorage (XSS vulnerable), httpOnly cookie (CSRF vulnerable but more secure)
    public string Token { get; set; } = string.Empty;
    
    // When the token expires - client can use this to refresh before expiration
    public DateTime Expiration { get; set; }
    
    // User info for display purposes (not for authorization decisions)
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

/// <summary>
/// Request model for user registration
/// </summary>
public class RegisterRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}
