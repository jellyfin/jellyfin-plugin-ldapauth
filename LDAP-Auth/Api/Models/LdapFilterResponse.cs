namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Response for querying LDAP filters.
    /// </summary>
    public class LdapFilterResponse
    {
        /// <summary>
        /// Gets or sets the number of users found by the user filter.
        /// </summary>
        public int Users { get; set; }

        /// <summary>
        /// Gets or sets the number of users found by the admin filter.
        /// </summary>
        public int Admins { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether admins is a subset of users.
        /// </summary>
        public bool IsSubset { get; set; }
    }
}
