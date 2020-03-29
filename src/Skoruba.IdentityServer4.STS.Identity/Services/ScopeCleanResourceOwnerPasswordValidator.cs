using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.AspNetIdentity;
using IdentityServer4.Events;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity;

namespace Skoruba.IdentityServer4.STS.Identity.Services
{
    public class ScopeCleanResourceOwnerPasswordValidator<TUser, TRole> : ResourceOwnerPasswordValidator<TUser>
        where TUser : UserIdentity
        where TRole : UserIdentityRole
    {
        private readonly UserManager<TUser> _userManager;
        private readonly RoleManager<TRole> _roleManager;

        public ScopeCleanResourceOwnerPasswordValidator(UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            SignInManager<TUser> signInManager,
            IEventService events,
            ILogger<ResourceOwnerPasswordValidator<TUser>> logger) :
            base(userManager, signInManager, events, logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public override async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            await base.ValidateAsync(context).ConfigureAwait(false);
            if (!context.Result.IsError)
            {
                var user = await _userManager.Users
                    .Include(u => u.AllowedScopes)
                    .FirstOrDefaultAsync(u => u.UserName == context.UserName)
                    .ConfigureAwait(false);

                IEnumerable<string> allowedScopes = user.AllowedScopes?.Select(s => s.Scope) ?? Array.Empty<string>();

                var roleNames = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
                var roles = await _roleManager.Roles
                    .Include(r => r.AllowedScopes)
                    .Where(r => roleNames.Contains(r.Name))
                    .ToArrayAsync()
                    .ConfigureAwait(false);

                allowedScopes = allowedScopes.Concat(roles.SelectMany(r => r.AllowedScopes?.Select(s => s.Scope) ?? Array.Empty<string>()));

                var scopes = context.Request.Scopes.Join(allowedScopes, k => k, k => k, (a, b) => a);
                context.Request.Scopes = new HashSet<string>(scopes);

                if (context.Request.ValidatedScopes.GrantedResources.ApiResources != null)
                {
                    foreach (var resource in context.Request.ValidatedScopes.GrantedResources.ApiResources)
                    {
                        foreach (var scope in resource.Scopes.ToArray())
                        {
                            if (!context.Request.Scopes.Contains(scope.Name))
                            {
                                resource.Scopes.Remove(scope);
                            }
                        }
                    }
                }

                if (context.Request.ValidatedScopes.GrantedResources.IdentityResources != null)
                {
                    foreach (var resource in context.Request.ValidatedScopes.GrantedResources.IdentityResources.ToArray())
                    {
                        if (!context.Request.Scopes.Contains(resource.Name))
                        {
                            context.Request.ValidatedScopes.GrantedResources.IdentityResources.Remove(resource);
                        }
                    }
                }
            }
        }
    }
}
