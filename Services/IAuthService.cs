using AuthorizeAdvanced.Models;

namespace AuthorizeAdvanced.Services
{
    public interface IAuthService
    {
        Task<TokenResponse> LoginAsync(LoginRequest request, string ipAddress);
        Task<TokenResponse> RefreshTokenAsync(string refreshToken, string ipAddress);
        Task<bool> RevokeTokenAsync(string refreshToken, string ipAddress);
        Task<bool> LogoutAsync(string refreshToken);
    }
}
