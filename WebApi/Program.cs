using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// JWT AUTHENTICATION CONFIGURATION
// ============================================================================
// JWT (JSON Web Token) is a stateless authentication mechanism.
// The server doesn't store session data - all info is in the token itself.
// Benefits: Scalable (no session storage), works across services, mobile-friendly

// Get JWT settings from configuration (appsettings.json)
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];

// Add Authentication services with JWT Bearer scheme
builder.Services.AddAuthentication(options =>
{
    // Set JWT Bearer as the default authentication scheme
    // This means [Authorize] attribute will use JWT by default
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Token validation parameters - how the server validates incoming tokens
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Validate the signing key - ensures token wasn't tampered with
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!)),
        
        // Validate the issuer (who created the token)
        // Set to false if you have multiple token issuers
        ValidateIssuer = true,
        ValidIssuer = jwtSettings["Issuer"],
        
        // Validate the audience (who the token is intended for)
        // Set to false if token is used across multiple applications
        ValidateAudience = true,
        ValidAudience = jwtSettings["Audience"],
        
        // Validate token expiration
        ValidateLifetime = true,
        
        // Clock skew compensates for server time differences
        // Default is 5 minutes - set to zero for stricter validation
        ClockSkew = TimeSpan.Zero
    };

    // Optional: Handle JWT events for logging or custom logic
    options.Events = new JwtBearerEvents
    {
        // Called when authentication fails
        OnAuthenticationFailed = context =>
        {
            // Log the error (in production, use proper logging)
            Console.WriteLine($"Authentication failed: {context.Exception.Message}");
            return Task.CompletedTask;
        },
        
        // Called when a token is validated successfully
        OnTokenValidated = context =>
        {
            // You can add custom validation logic here
            // e.g., check if user still exists in database
            Console.WriteLine($"Token validated for: {context.Principal?.Identity?.Name}");
            return Task.CompletedTask;
        }
    };
});

// Add Authorization services
builder.Services.AddAuthorization();

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// ============================================================================
// SWAGGER CONFIGURATION WITH JWT SUPPORT
// ============================================================================
// Configure Swagger to include JWT authentication UI
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "WebApi with JWT Authentication",
        Version = "v1",
        Description = "A .NET Web API with JWT Bearer token authentication"
    });

    // Add JWT Authentication to Swagger
    // This adds the "Authorize" button in Swagger UI
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token in the text input below.\n\n" +
                      "Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    });

    // Apply JWT authentication globally to all endpoints
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
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// ============================================================================
// AUTHENTICATION & AUTHORIZATION MIDDLEWARE ORDER
// ============================================================================
// IMPORTANT: Order matters! Authentication must come before Authorization
// 1. UseAuthentication() - Validates the JWT token and sets User identity
// 2. UseAuthorization() - Checks if the authenticated user has permission

app.UseAuthentication(); // Must be before UseAuthorization
app.UseAuthorization();

app.MapControllers();

app.Run();
