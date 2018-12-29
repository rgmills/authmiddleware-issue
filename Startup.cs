using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace authmiddleware
{
    public class Startup
    {
        public static SymmetricSecurityKey BearerKey1 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1F~e`c8p@jPorkC6.1uWD!2qyHL)apTR7ELZA08ghkzZB{dcUW}dS6[YhK]h7|12"))
        {
            KeyId = "bearer1"
        };

        public static SymmetricSecurityKey BearerKey2 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1F~e`c8p@jPorkC6.1uWD!2qyHL)apTR7ELZA08ghkzZB{dcUW}dS6[YhK]h7|13"))
        {
            KeyId = "bearer2"
        };

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddAuthentication(opts =>
            {
                opts.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opts.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer("Bearer", "Bearer 1", opts =>
                {
                    opts.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = true,
                        
                        ClockSkew = TimeSpan.FromMinutes(5),

                        IssuerSigningKeys = new[] { BearerKey1 },
                    };
                })
                .AddJwtBearer("Bearer2", "Bearer 2", opts =>
                {
                    opts.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = true,

                        ClockSkew = TimeSpan.FromMinutes(5),

                        IssuerSigningKeys = new[] { BearerKey2 },

                        AuthenticationType = "Bearer2"
                    };
                });

            services.AddAuthorization(opts =>
            {
                opts.AddPolicy("Bearer1Policy", policy =>
                {
                    policy.AddAuthenticationSchemes("Bearer");
                    policy.RequireClaim(ClaimTypes.Name);
                });

                opts.AddPolicy("Bearer2Policy", policy =>
                {
                    policy.AddAuthenticationSchemes("Bearer2");
                    policy.RequireClaim(ClaimTypes.Name);
                });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();

            app.UseMiddleware<ContextMiddleware>();

            app.UseMvc();
        }
    }


    public class ContextMiddleware
    {
        private RequestDelegate _next;
        public ContextMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public Task Invoke(HttpContext context, ILogger<ContextMiddleware> logger)
        {
            logger.LogInformation($"context.User.Identity.IsAuthenticated = {context.User.Identity.IsAuthenticated}");

            return _next(context);
        }
    }

    [Route("[controller]")]
    public class SampleController : Controller
    {
        private JwtSecurityTokenHandler JwtSecurityTokenHandler { get; } = new JwtSecurityTokenHandler();

        private string GetToken(SecurityKey key)
        {
            var claimsIdentity = new ClaimsIdentity();
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, "test@test.com"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(key, "HS512")
            };

            var securityToken = JwtSecurityTokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            return JwtSecurityTokenHandler.WriteToken(securityToken);
        }

        [HttpGet("bearer1")]
        [AllowAnonymous]
        public IActionResult GetBearer1Token()
        {
            var token = GetToken(Startup.BearerKey1);

            return Ok(new { token });
        }

        [HttpGet("bearer2")]
        [AllowAnonymous]
        public IActionResult GetBearer2Token()
        {
            var token = GetToken(Startup.BearerKey2);

            return Ok(new { token });
        }

        [HttpPost("bearer1")]
        [Authorize("Bearer1Policy")]
        public IActionResult UseBearer1Policy()
        {
            return Ok(new { HttpContext.User.Identity.AuthenticationType });
        }

        [HttpPost("bearer2")]
        [Authorize("Bearer2Policy")]
        public IActionResult UseBearer2Policy()
        {
            return Ok(new { HttpContext.User.Identity.AuthenticationType });
        }
    }
}
