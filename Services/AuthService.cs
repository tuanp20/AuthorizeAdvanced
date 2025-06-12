using AuthorizeAdvanced.Configuration;
using AuthorizeAdvanced.Data;
using AuthorizeAdvanced.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizeAdvanced.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly JwtSettings _jwtSettings;
        private readonly ITokenBlacklistService _blacklistService;

        public AuthService(
            ApplicationDbContext context,
            IOptions<JwtSettings> jwtSettings,
            ITokenBlacklistService blacklistService)
        {
            _context = context;
            _jwtSettings = jwtSettings.Value;
            _blacklistService = blacklistService;
        }

        public async Task<TokenResponse> LoginAsync(LoginRequest request, string ipAddress)
        {
            var user = await _context.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Username == request.Username && u.IsActive);

            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                throw new UnauthorizedAccessException("Invalid credentials");
            }

            var jwtToken = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken(ipAddress);

            user.RefreshTokens.Add(refreshToken);
            RemoveOldRefreshTokens(user);

            await _context.SaveChangesAsync();

            return new TokenResponse
            {
                AccessToken = jwtToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes)
            };
        }

        public async Task<TokenResponse> RefreshTokenAsync(string refreshToken, string ipAddress)
        {
            var user = await GetUserByRefreshTokenAsync(refreshToken);
            var oldRefreshToken = user.RefreshTokens.Single(x => x.Token == refreshToken);

            if (oldRefreshToken.IsRevoked)
            {
                // Revoke all descendant tokens in case this token has been compromised
                RevokeDescendantRefreshTokens(oldRefreshToken, user, ipAddress,
                    $"Attempted reuse of revoked ancestor token: {refreshToken}");
                await _context.SaveChangesAsync();
            }

            if (!oldRefreshToken.IsActive)
                throw new SecurityTokenException("Invalid token");

            // Replace old refresh token with a new one (rotate token)
            var newRefreshToken = RotateRefreshToken(oldRefreshToken, ipAddress);
            user.RefreshTokens.Add(newRefreshToken);
            RemoveOldRefreshTokens(user);

            await _context.SaveChangesAsync();

            var jwtToken = GenerateJwtToken(user);

            return new TokenResponse
            {
                AccessToken = jwtToken,
                RefreshToken = newRefreshToken.Token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes)
            };
        }

        public async Task<bool> RevokeTokenAsync(string refreshToken, string ipAddress)
        {
            var user = await GetUserByRefreshTokenAsync(refreshToken);
            var token = user.RefreshTokens.Single(x => x.Token == refreshToken);

            if (!token.IsActive)
                return false;

            // Revoke token and save
            RevokeRefreshToken(token, ipAddress, "Revoked without replacement");
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
                return false;

            var user = await GetUserByRefreshTokenAsync(refreshToken);
            var token = user.RefreshTokens.Single(x => x.Token == refreshToken);

            if (token.IsActive)
            {
                RevokeRefreshToken(token, "", "Logged out");
                await _context.SaveChangesAsync();
            }

            return true;
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);
            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[64];
            rngCryptoServiceProvider.GetBytes(randomBytes);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                CreatedAt = DateTime.UtcNow,
                CreatedByIp = ipAddress,
                IsActive = true
            };
        }

        private RefreshToken RotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = GenerateRefreshToken(ipAddress);
            RevokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
            return newRefreshToken;
        }

        private void RemoveOldRefreshTokens(User user)
        {
            // Remove old inactive refresh tokens from user based on TTL in app settings
            var refreshTokenTTL = _jwtSettings.RefreshTokenExpirationDays;
            user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.CreatedAt.AddDays(refreshTokenTTL) <= DateTime.UtcNow);
        }

        private async Task<User> GetUserByRefreshTokenAsync(string token)
        {
            var user = await _context.Users
                .Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

            if (user == null)
                throw new SecurityTokenException("Invalid token");

            return user;
        }

        private void RevokeDescendantRefreshTokens(RefreshToken refreshToken, User user,
            string ipAddress, string reason)
        {
            // Recursively traverse the refresh token chain and ensure all descendants are revoked
            if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
            {
                var childToken = user.RefreshTokens
                    .SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
                if (childToken != null && childToken.IsActive)
                {
                    RevokeRefreshToken(childToken, ipAddress, reason);
                    RevokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
                }
            }
        }

        private void RevokeRefreshToken(RefreshToken token, string ipAddress,
            string reason = null, string replacedByToken = null)
        {
            token.IsActive = false;
            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
            token.ReasonRevoked = reason;
            token.ReplacedByToken = replacedByToken;
        }
    }
}
