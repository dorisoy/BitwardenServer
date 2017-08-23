using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Bit.Api.Utilities;
using Bit.Core;
using Bit.Core.Identity;
using System.Linq;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Serialization;
using AspNetCoreRateLimit;
using Bit.Api.Middleware;
using Serilog.Events;
using Stripe;
using Bit.Core.Utilities;
using IdentityModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Threading.Tasks;

namespace Bit.Api
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .AddSettingsConfiguration(env, "bitwarden-Api");
            Configuration = builder.Build();
            Environment = env;
        }

        public IConfigurationRoot Configuration { get; private set; }
        public IHostingEnvironment Environment { get; set; }

        public void ConfigureServices(IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();

            // Options
            services.AddOptions();

            // Settings
            var globalSettings = services.AddGlobalSettingsServices(Configuration);
            if(!globalSettings.SelfHosted)
            {
                services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimitOptions"));
                services.Configure<IpRateLimitPolicies>(Configuration.GetSection("IpRateLimitPolicies"));
            }

            // Data Protection
            services.AddCustomDataProtectionServices(Environment, globalSettings);

            // Stripe Billing
            StripeConfiguration.SetApiKey(globalSettings.StripeApiKey);

            // Repositories
            services.AddSqlServerRepositories();

            // Context
            services.AddScoped<CurrentContext>();

            // Caching
            services.AddMemoryCache();

            if(!globalSettings.SelfHosted)
            {
                // Rate limiting
                services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
                services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
            }

            // Identity
            services.AddCustomIdentityServices(globalSettings);

            services.AddAuthorization(config =>
            {
                config.AddPolicy("Application", policy =>
                {
                    //policy.AddAuthenticationSchemes("Bearer"/*, "Bearer3"*/);
                    policy.RequireAuthenticatedUser();
                    //policy.RequireClaim(JwtClaimTypes.AuthenticationMethod, "Application");
                    //policy.RequireClaim(JwtClaimTypes.Scope, "api");
                });
                config.AddPolicy("Web", policy =>
                {
                    policy.AddAuthenticationSchemes("Bearer"/*, "Bearer3"*/);
                    policy.RequireAuthenticatedUser();
                    policy.RequireClaim(JwtClaimTypes.AuthenticationMethod, "Application");
                    policy.RequireClaim(JwtClaimTypes.Scope, "api");
                    policy.RequireClaim(JwtClaimTypes.ClientId, "web");
                });
                config.AddPolicy("Push", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.RequireClaim(JwtClaimTypes.Scope, "api.push");
                });
            });

            services.AddAuthentication(o =>
            {
                //o.DefaultScheme = "Bearer";
                //o.AddScheme("Bearer3", b => b.Build());
            })
            .AddJwtBearer(o =>
            {
                SetJwtOptions(o, globalSettings);
            });

            services.AddScoped<AuthenticatorTokenProvider>();

            // Services
            services.AddBaseServices();
            services.AddDefaultServices(globalSettings);

            // Cors
            services.AddCors(config =>
            {
                config.AddPolicy("All", policy =>
                    policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin().SetPreflightMaxAge(TimeSpan.FromDays(1)));
            });

            // MVC
            services.AddMvc(config =>
            {
                config.Filters.Add(new ExceptionHandlerFilterAttribute());
                config.Filters.Add(new ModelStateValidationFilterAttribute());

                // Allow JSON of content type "text/plain" to avoid cors preflight
                var textPlainMediaType = MediaTypeHeaderValue.Parse("text/plain");
                foreach(var jsonFormatter in config.InputFormatters.OfType<JsonInputFormatter>())
                {
                    jsonFormatter.SupportedMediaTypes.Add(textPlainMediaType);
                }
            }).AddJsonOptions(options => options.SerializerSettings.ContractResolver = new DefaultContractResolver());
        }

        public void Configure(
            IApplicationBuilder app,
            IHostingEnvironment env,
            ILoggerFactory loggerFactory,
            IApplicationLifetime appLifetime,
            GlobalSettings globalSettings)
        {
            loggerFactory
                .AddSerilog(env, appLifetime, globalSettings, (e) =>
                {
                    var context = e.Properties["SourceContext"].ToString();
                    if(e.Exception != null && (e.Exception.GetType() == typeof(SecurityTokenValidationException) ||
                        e.Exception.Message == "Bad security stamp."))
                    {
                        return false;
                    }

                    if(context.Contains(typeof(IpRateLimitMiddleware).FullName) && e.Level == LogEventLevel.Information)
                    {
                        return true;
                    }

                    if(context.Contains("IdentityServer4.Validation.TokenRequestValidator"))
                    {
                        return e.Level > LogEventLevel.Error;
                    }

                    return e.Level >= LogEventLevel.Error;
                })
                .AddDebug();

            // Forwarded headers
            if(!env.IsDevelopment())
            {
                app.UseForwardedHeadersForAzure();
            }

            if(!globalSettings.SelfHosted)
            {
                // Rate limiting
                app.UseMiddleware<CustomIpRateLimitMiddleware>();
            }

            // Add static files to the request pipeline.
            app.UseStaticFiles();

            // Add Cors
            app.UseCors("All");

            // Add authentication to the request pipeline.
            app.UseAuthentication();
                //.AllowScopes(new string[] { "api", "api.push" });

            // Add current context
            app.UseMiddleware<CurrentContextMiddleware>();

            // Add MVC to the request pipeline.
            app.UseMvc();
        }

        private void SetJwtOptions(JwtBearerOptions options, GlobalSettings globalSettings)
        {
            if(!string.IsNullOrWhiteSpace(globalSettings.BaseServiceUri.InternalIdentity))
            {
                options.Authority = globalSettings.BaseServiceUri.InternalIdentity;
            }
            else
            {
                options.Authority = globalSettings.BaseServiceUri.Identity;
            }

            options.RequireHttpsMetadata = options.Authority.StartsWith("https");
            options.TokenValidationParameters.ValidateAudience = false;
            options.RefreshOnIssuerKeyNotFound = true;
            options.SaveToken = true;
            options.BackchannelTimeout = TimeSpan.FromSeconds(60);
            options.TokenValidationParameters.NameClaimType = JwtClaimTypes.Email;
            options.TokenValidationParameters.RoleClaimType = JwtClaimTypes.Role;

            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = (e) =>
                {
                    if(e.Scheme.Name.Equals("Bearer"))
                    {
                        e.Token = TokenRetrieval.FromAuthorizationHeaderOrQueryString(e.Request);
                    }
                    else if(e.Scheme.Name.Equals("Bearer3"))
                    {
                        e.Token = TokenRetrieval.FromAuthorizationHeaderOrQueryString(e.Request, "Bearer3", "access_token3");
                    }
                    return Task.FromResult(0);
                }
            };
        }
    }
}
