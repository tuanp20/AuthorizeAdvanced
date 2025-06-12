using AuthorizeAdvanced.Services;
using System.IdentityModel.Tokens.Jwt;

namespace AuthorizeAdvanced.Middleware
{
    public class TokenRevocationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ITokenBlacklistService _blacklistService;
        private readonly ILogger<TokenRevocationMiddleware> _logger;

        public TokenRevocationMiddleware(
            RequestDelegate next,
            ITokenBlacklistService blacklistService,
            ILogger<TokenRevocationMiddleware> logger)
        {
            _next = next;
            _blacklistService = blacklistService;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"]
                .FirstOrDefault()?.Split(" ").Last();

            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    var jsonToken = handler.ReadJwtToken(token);
                    var jti = jsonToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;

                    if (!string.IsNullOrEmpty(jti) && _blacklistService.IsTokenRevoked(jti))
                    {
                        _logger.LogWarning($"Revoked token attempted to be used: {jti}");
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Token has been revoked");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error checking token revocation status");
                }
            }

            await _next(context);
        }
    }
}
