using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace WebApi.Controllers;

/// <summary>
/// Weather Forecast Controller - Demonstrates JWT Authorization
/// 
/// Authorization Attributes:
/// - [Authorize] - Requires any authenticated user
/// - [Authorize(Roles = "Admin")] - Requires user with Admin role
/// - [Authorize(Roles = "Admin,Manager")] - Requires Admin OR Manager role
/// - [AllowAnonymous] - Allows unauthenticated access (overrides [Authorize])
/// </summary>
[ApiController]
[Route("[controller]")]
[Authorize] // Requires authentication for all endpoints in this controller
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Get weather forecast - Requires authentication (any valid JWT token)
    /// 
    /// To access this endpoint:
    /// 1. Call POST /api/auth/login with valid credentials
    /// 2. Copy the token from the response
    /// 3. Click "Authorize" in Swagger UI and paste the token
    /// 4. Call this endpoint
    /// </summary>
    [HttpGet(Name = "GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        // Access user claims from the JWT token
        // These were set during token generation in AuthController
        var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value 
                    ?? User.FindFirst("sub")?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var userId = User.FindFirst("userId")?.Value;

        _logger.LogInformation("Weather forecast requested by user: {Username}, Role: {Role}, UserId: {UserId}", 
            username, role, userId);

        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    /// <summary>
    /// Post endpoint - Requires authentication
    /// </summary>
    [HttpPost(Name = "GetCustomData")]
    public string Post()
    {
        // Get the authenticated user's name from the token
        var username = User.Identity?.Name ?? "Unknown";
        return $"Hello, {username}!";
    }

    /// <summary>
    /// Admin-only endpoint - Requires Admin role
    /// 
    /// Role-based authorization checks the ClaimTypes.Role claim in the JWT.
    /// Only users with Role = "Admin" can access this endpoint.
    /// Returns 403 Forbidden if user doesn't have the required role.
    /// </summary>
    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new { message = "Welcome, Admin! You have access to admin-only resources." });
    }

    /// <summary>
    /// Public endpoint - No authentication required
    /// 
    /// [AllowAnonymous] overrides the controller-level [Authorize] attribute.
    /// Use this for endpoints that should be publicly accessible.
    /// </summary>
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult PublicEndpoint()
    {
        return Ok(new { message = "This is a public endpoint - no authentication required!" });
    }
}
