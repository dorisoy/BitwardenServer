using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Bit.Core;
using Bit.Core.Utilities;
using AspNetCoreRateLimit;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using IdentityServer4;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace Bit.Identity
{
    public class Startup
    {
        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("en-US");
            Configuration = configuration;
            Environment = env;
        }

        public IConfiguration Configuration { get; private set; }
        public IWebHostEnvironment Environment { get; set; }

        public void ConfigureServices(IServiceCollection services)
        {
            // Options
            services.AddOptions();

            // Settings
            var globalSettings = services.AddGlobalSettingsServices(Configuration);
            if (!globalSettings.SelfHosted)
            {
                services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimitOptions"));
                services.Configure<IpRateLimitPolicies>(Configuration.GetSection("IpRateLimitPolicies"));
            }

            // Data Protection
            services.AddCustomDataProtectionServices(Environment, globalSettings);

            // Repositories
            services.AddSqlServerRepositories(globalSettings);

            // Context
            services.AddScoped<CurrentContext>();

            // Caching
            services.AddMemoryCache();

            // Mvc
            services.AddMvc();

            if (!globalSettings.SelfHosted)
            {
                // Rate limiting
                services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
                services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
            }

            services.AddControllersWithViews();

            services.AddAuthentication()
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, "Okta", options =>
                {
                    // options.RequireHttpsMetadata = false;
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                    options.SaveTokens = true;

                    options.Authority = "https://dev-836655-admin.oktapreview.com/oauth2/default";
                    options.ClientId = "0oapydhli2JggD5VT0h7";
                    options.ClientSecret = "j4elmBNfKPVJpDomn9nu0_DZQ0eeYTrfvWZhEjkA";
                    options.ResponseType = "code";

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };
                });

            // IdentityServer
            services.AddCustomIdentityServerServices(Environment, globalSettings);

            // Identity
            services.AddCustomIdentityServices(globalSettings);

            // Services
            services.AddBaseServices();
            services.AddDefaultServices(globalSettings);

            if (CoreHelpers.SettingHasValue(globalSettings.ServiceBus.ConnectionString) &&
                CoreHelpers.SettingHasValue(globalSettings.ServiceBus.ApplicationCacheTopicName))
            {
                services.AddHostedService<Core.HostedServices.ApplicationCacheHostedService>();
            }
        }

        public void Configure(
            IApplicationBuilder app,
            IWebHostEnvironment env,
            IHostApplicationLifetime appLifetime,
            GlobalSettings globalSettings,
            ILogger<Startup> logger)
        {
            IdentityModelEventSource.ShowPII = true;
            app.UseSerilog(env, appLifetime, globalSettings);

            // Default Middleware
            app.UseDefaultMiddleware(env, globalSettings);

            if (!globalSettings.SelfHosted)
            {
                // Rate limiting
                app.UseMiddleware<CustomIpRateLimitMiddleware>();
            }
            else
            {
                app.UseForwardedHeaders(globalSettings);
            }

            // Add static files to the request pipeline.
            app.UseStaticFiles();

            // Add routing
            app.UseRouting();

            // Add Cors
            app.UseCors(policy => policy.SetIsOriginAllowed(h => true)
                .AllowAnyMethod().AllowAnyHeader().AllowCredentials());

            // Add current context
            app.UseMiddleware<CurrentContextMiddleware>();

            // Add IdentityServer to the request pipeline.
            app.UseIdentityServer();

            // Add Mvc stuff
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());

            // Log startup
            logger.LogInformation(Constants.BypassFiltersEventId, globalSettings.ProjectName + " started.");
        }
    }
}
