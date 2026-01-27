using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Models;

namespace WebApi.Controllers;

/// <summary>
/// JWT Authentication Controller
/// 
/// JWT (JSON Web Token) Flow:
/// 1. Client sends credentials (username/password) to /api/auth/login
/// 2. Server validates credentials against user store
/// 3. If valid, server generates a signed JWT containing user claims
/// 4. Client stores the token (typically in localStorage or httpOnly cookie)
/// 5. Client includes token in Authorization header for subsequent requests:
///    Authorization: Bearer <token>
/// 6. Server validates token signature and expiration on each request
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    // In production, use a database or identity provider (e.g., ASP.NET Identity, Auth0)
    // This is a simplified in-memory user store for demonstration
    private static readonly List<User> _users = new()
    {
        new User { Id = 1, Username = "admin", Password = "admin123", Email = "admin@example.com", Role = "Admin" },
        new User { Id = 2, Username = "user", Password = "user123", Email = "user@example.com", Role = "User" }
    };

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    /// <summary>
    /// Authenticates user and returns a JWT token
    /// 
    /// Request body: { "username": "admin", "password": "admin123" }
    /// Response: { "token": "eyJhbGciOiJIUzI1NiIs...", "expiration": "2024-01-01T12:00:00Z" }
    /// </summary>
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // Step 1: Validate the request
        if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { message = "Username and password are required" });
        }

        // Step 2: Authenticate user against the user store
        // WARNING: In production, NEVER store plain-text passwords
        // Use password hashing (e.g., BCrypt, Argon2, or ASP.NET Identity's PasswordHasher)
        var user = _users.FirstOrDefault(u => 
            u.Username == request.Username && 
            u.Password == request.Password);

        if (user == null)
        {
            // Return 401 Unauthorized for invalid credentials
            // Avoid revealing whether username or password was incorrect (security best practice)
            return Unauthorized(new { message = "Invalid credentials" });
        }

        // Step 3: Generate JWT token
        var token = GenerateJwtToken(user);

        return Ok(new LoginResponse
        {
            Token = token,
            Expiration = DateTime.UtcNow.AddMinutes(
                Convert.ToDouble(_configuration["JwtSettings:ExpirationInMinutes"])),
            Username = user.Username,
            Role = user.Role
        });
    }

    /// <summary>
    /// Generates a JWT token for the authenticated user
    /// 
    /// Token Structure (3 parts separated by dots):
    /// 1. Header: Algorithm and token type (e.g., {"alg": "HS256", "typ": "JWT"})
    /// 2. Payload: Claims (user data and metadata)
    /// 3. Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
    /// </summary>
    private string GenerateJwtToken(User user)
    {
        // Get JWT settings from configuration
        var secretKey = _configuration["JwtSettings:SecretKey"];
        var issuer = _configuration["JwtSettings:Issuer"];
        var audience = _configuration["JwtSettings:Audience"];
        var expirationMinutes = Convert.ToDouble(_configuration["JwtSettings:ExpirationInMinutes"]);

        // Create the signing key from the secret
        // The key must be at least 256 bits (32 characters) for HS256
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!));
        
        // Create signing credentials using HMAC-SHA256 algorithm
        // Other options: RS256 (RSA), ES256 (ECDSA) for asymmetric signing
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Define claims - these are statements about the user
        // Claims are included in the token payload and can be read by the server
        var claims = new[]
        {
            // Subject (sub): Unique identifier for the user
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            
            // JWT ID (jti): Unique identifier for this specific token
            // Useful for token revocation and preventing replay attacks
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            
            // Issued At (iat): When the token was created
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            
            // Email claim
            new Claim(ClaimTypes.Email, user.Email),
            
            // Role claim - used for role-based authorization
            // Enables [Authorize(Roles = "Admin")] attribute
            new Claim(ClaimTypes.Role, user.Role),
            
            // Custom claim for user ID
            new Claim("userId", user.Id.ToString())
        };

        // Create the token with all components
        var token = new JwtSecurityToken(
            issuer: issuer,           // Who created the token
            audience: audience,        // Who the token is intended for
            claims: claims,            // User data and metadata
            notBefore: DateTime.UtcNow, // Token is not valid before this time
            expires: DateTime.UtcNow.AddMinutes(expirationMinutes), // Token expiration
            signingCredentials: credentials // How the token is signed
        );

        // Serialize the token to a string
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Register a new user (simplified implementation)
    /// In production, add email verification, password strength validation, etc.
    /// </summary>
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest request)
    {
        if (request == null || string.IsNullOrEmpty(request.Username) || 
            string.IsNullOrEmpty(request.Password) || string.IsNullOrEmpty(request.Email))
        {
            return BadRequest(new { message = "All fields are required" });
        }

        // Check if username already exists
        if (_users.Any(u => u.Username == request.Username))
        {
            return Conflict(new { message = "Username already exists" });
        }

        // Create new user
        // WARNING: In production, hash the password before storing
        var newUser = new User
        {
            Id = _users.Max(u => u.Id) + 1,
            Username = request.Username,
            Password = request.Password, // Should be hashed!
            Email = request.Email,
            Role = "User" // Default role
        };

        _users.Add(newUser);

        return CreatedAtAction(nameof(Login), new { message = "User registered successfully" });
    }

    [HttpPost("GetInfoData")]
    public IActionResult GetPredefinedString()
    {
        return Ok("GetData");
    }
}
