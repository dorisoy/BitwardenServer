using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Bit.Core.Models.Table;
using Bit.Core.Repositories;
using Bit.Identity.Models;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Bit.Identity.Controllers
{
    public class AccountController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IUserRepository userRepository,
            ILogger<AccountController> logger)
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _userRepository = userRepository;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            return RedirectToAction(nameof(ExternalChallenge),
                new { provider = await GetProviderAsync(returnUrl), returnUrl });
        }

        /// <summary>
        /// initiate roundtrip to external authentication provider
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalChallenge(string provider, string returnUrl)
        {
            if(string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // validate returnUrl - either it is a valid OIDC URL or back to a local page
            if(Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            }

            // start challenge and roundtrip the return URL and scheme 
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(ExternalCallback)),
                Items =
                {
                    { "returnUrl", returnUrl },
                    { "scheme", provider },
                }
            };

            return Challenge(props, provider);
        }

        /// <summary>
        /// Post processing of external authentication
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalCallback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(
                IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if(result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            if(_logger.IsEnabled(LogLevel.Debug))
            {
                var externalClaims = result.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
                _logger.LogDebug("External claims: {@claims}", externalClaims);
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);
            if(user == null)
            {
                // this might be where you might initiate a custom workflow for user registration
                // in this sample we don't show how that would be done, as our sample implementation
                // simply auto-provisions new external user
                user = await AutoProvisionUserAsync(provider, providerUserId, claims);
            }

            // this allows us to collect any additonal claims or properties
            // for the specific prtotocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForWsFed(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForSaml2p(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user
            await HttpContext.SignInAsync(user.Id.ToString(), user.Email, provider, localSignInProps, additionalLocalClaims.ToArray());

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // retrieve return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // check if external login is in the context of an OIDC request
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            if(context != null)
            {
                if(await IsPkceClientAsync(context.ClientId))
                {
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    return View("Redirect", new RedirectViewModel { RedirectUrl = returnUrl });
                }
            }

            return Redirect(returnUrl);
        }


        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logged out page knows what to display
            var (updatedLogoutId, redirectUri, externalAuthenticationScheme) = await GetLoggedOutDataAsync(logoutId);

            if(User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();
            }

            if(externalAuthenticationScheme != null)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                var url = Url.Action("Logout", new { logoutId = updatedLogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, externalAuthenticationScheme);
            }
            if(redirectUri != null)
            {
                return View("Redirect", new RedirectViewModel { RedirectUrl = redirectUri });
            }
            else
            {
                return Redirect("~/");
            }
        }

        private async Task<(User user, string provider, string providerUserId, IEnumerable<Claim> claims)>
            FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // TODO: find external user
            // var user = _users.FindByExternalProvider(provider, providerUserId);
            var user = await _userRepository.GetByEmailAsync("hello@bitwarden.com");

            return (user, provider, providerUserId, claims);
        }

        private async Task<User> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            // TODO: provision external user
            //var user = _users.AutoProvisionUser(provider, providerUserId, claims.ToList());
            var user = await _userRepository.GetByEmailAsync("hello@bitwarden.com");
            return user;
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if(sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if(id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }

        private void ProcessLoginCallbackForWsFed(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }

        private void ProcessLoginCallbackForSaml2p(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }

        private async Task<string> GetProviderAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if(context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                return context.IdP;
            }
            var schemes = await _schemeProvider.GetAllSchemesAsync();
            var providers = schemes.Select(x => x.Name).ToList();
            return providers.FirstOrDefault();
        }

        private async Task<(string, string, string)> GetLoggedOutDataAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);
            string externalAuthenticationScheme = null;
            if(User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if(idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if(providerSupportsSignout)
                    {
                        if(logoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            logoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        externalAuthenticationScheme = idp;
                    }
                }
            }

            return (logoutId, logout?.PostLogoutRedirectUri, externalAuthenticationScheme);
        }

        public async Task<bool> IsPkceClientAsync(string client_id)
        {
            if(!string.IsNullOrWhiteSpace(client_id))
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(client_id);
                return client?.RequirePkce == true;
            }
            return false;
        }
    }
}
