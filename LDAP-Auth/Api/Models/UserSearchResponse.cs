namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Response for querying for user.
    /// </summary>
    public class UserSearchResponse
    {
        /// <summary>
        /// Gets or sets the located user DN.
        /// </summary>
        public string LocatedDn { get; set; }
    }
}
