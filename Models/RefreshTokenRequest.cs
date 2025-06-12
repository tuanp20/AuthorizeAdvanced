using System.ComponentModel.DataAnnotations;

namespace AuthorizeAdvanced.Models
{
    public class RefreshTokenRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
