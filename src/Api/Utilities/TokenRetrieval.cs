using Microsoft.AspNetCore.Http;
using System;
using System.Linq;

namespace Bit.Api.Utilities
{
    public static class TokenRetrieval
    {
        public static string FromAuthorizationHeaderOrQueryString(HttpRequest request, string headerScheme = "Bearer",
            string qsName = "access_token")
        {
            string authorization = request.Headers["Authorization"].FirstOrDefault();

            if(string.IsNullOrWhiteSpace(authorization))
            {
                return request.Query[qsName].FirstOrDefault();
            }

            if(authorization.StartsWith(headerScheme + " ", StringComparison.OrdinalIgnoreCase))
            {
                return authorization.Substring(headerScheme.Length + 1).Trim();
            }

            return null;
        }
    }
}
