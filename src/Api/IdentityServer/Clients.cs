using IdentityServer4.Models;
using System.Collections.Generic;

namespace Bit.Api.IdentityServer
{
    public class Clients
    {
        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new ApiClient("mobile", 60),
                new ApiClient("web", 1),
                new ApiClient("browser", 30),
                new ApiClient("desktop", 30)
            };
        }

        public class ApiClient : Client
        {
            public ApiClient(string id, int slidingDays)
            {
                ClientId = id;
                RequireClientSecret = false;
                AllowedGrantTypes = GrantTypes.ResourceOwnerPassword;
                RefreshTokenExpiration = TokenExpiration.Sliding;
                RefreshTokenUsage = TokenUsage.ReUse;
                SlidingRefreshTokenLifetime = 86400 * slidingDays;
                AbsoluteRefreshTokenLifetime = 86400 * 365 * 20; // 20 years
                UpdateAccessTokenClaimsOnRefresh = true;
                AccessTokenLifetime = 60 * 60 * 1; // 1 hour
                AllowOfflineAccess = true;
                AllowedScopes = new string[] { "api" };
            }
        }
    }
}
