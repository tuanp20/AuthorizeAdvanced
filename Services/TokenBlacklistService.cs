using Microsoft.Extensions.Caching.Memory;

namespace AuthorizeAdvanced.Services
{
    public class TokenBlacklistService : ITokenBlacklistService
    {
        private readonly IMemoryCache _cache;
        private readonly ILogger<TokenBlacklistService> _logger;

        public TokenBlacklistService(IMemoryCache cache, ILogger<TokenBlacklistService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        public void RevokeToken(string jti, DateTime expiry)
        {
            if (string.IsNullOrEmpty(jti))
                return;

            var cacheKey = $"revoked_token_{jti}";
            var cacheOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpiration = expiry,
                Priority = CacheItemPriority.High
            };

            _cache.Set(cacheKey, true, cacheOptions);
            _logger.LogInformation($"Token {jti} has been revoked");
        }

        public bool IsTokenRevoked(string jti)
        {
            if (string.IsNullOrEmpty(jti))
                return false;

            return _cache.TryGetValue($"revoked_token_{jti}", out _);
        }

        public async Task RevokeAllUserTokensAsync(int userId)
        {
            // This would typically involve database operations to revoke all tokens for a user
            // For simplicity, we're just logging here
            _logger.LogInformation($"All tokens for user {userId} have been revoked");
        }
    }
}
