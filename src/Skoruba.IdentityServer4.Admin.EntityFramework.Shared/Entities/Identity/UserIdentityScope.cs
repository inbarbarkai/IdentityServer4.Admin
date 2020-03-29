using System;
using System.Collections.Generic;
using System.Text;

namespace Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity
{
    public class UserIdentityScope
    {
        public int Id { get; set; }

        public string Scope { get; set; }

        public string UserId { get; set; }

        public UserIdentity User { get; set; }
    }
}
