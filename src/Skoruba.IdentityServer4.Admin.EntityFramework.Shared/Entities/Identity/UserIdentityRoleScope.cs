namespace Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity
{
    public class UserIdentityRoleScope
    {
        public int Id { get; set; }

        public string Scope { get; set; }

        public string RoleId { get; set; }

        public UserIdentityRole Role { get; set; }
    }
}
