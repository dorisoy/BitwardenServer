using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Linq;

namespace Bit.Core.IdentityServer
{
    public class StaticClients
    {
        public static IDictionary<string, Client> GetApiClients()
        {
            return new List<Client>
            {
                new ApiClient("mobile", 90, 1),
                new ApiClient("web", 30, 1),
                new ApiClient("browser", 30, 1),
                new ApiClient("desktop", 30, 1),
                new ApiClient("cli", 30, 1),
                new ApiClient("connector", 30, 24)
            }.ToDictionary(c => c.ClientId);
        }

        public class ApiClient : Client
        {
            public ApiClient(
                string id,
                int refreshTokenSlidingDays,
                int accessTokenLifetimeHours,
                string[] scopes = null)
            {
                ClientId = id;
                RequireClientSecret = false;
                AllowedGrantTypes = new List<string> { GrantType.ResourceOwnerPassword, GrantType.AuthorizationCode };
                RefreshTokenExpiration = TokenExpiration.Sliding;
                RefreshTokenUsage = TokenUsage.ReUse;
                SlidingRefreshTokenLifetime = 86400 * refreshTokenSlidingDays;
                AbsoluteRefreshTokenLifetime = 0; // forever
                UpdateAccessTokenClaimsOnRefresh = true;
                AccessTokenLifetime = 3600 * accessTokenLifetimeHours;
                AllowOfflineAccess = true;
                RequireConsent = false;
                RequirePkce = true;
                EnableLocalLogin = false;

                RedirectUris = new string[] { "http://localhost:5003/callback.html" };
                PostLogoutRedirectUris = new string[] { "http://localhost:5003/index.html" };
                AllowedCorsOrigins = new string[] { "http://localhost:5003" };

                var allowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId
                };
                if(scopes == null)
                {
                    allowedScopes.Add("api");
                }
                else
                {
                    allowedScopes.AddRange(scopes);
                }
                AllowedScopes = allowedScopes;
            }
        }
    }
}
