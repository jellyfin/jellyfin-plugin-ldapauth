using System.ComponentModel.DataAnnotations;
using Jellyfin.Plugin.LDAP_Auth.Config;

namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// A subset of <see cref="PluginConfiguration"/> containing just the settings for filtering users.
    /// </summary>
    public class UserFilterInfo
    {
        /// <summary>
        /// Gets or sets the ldap user search filter.
        /// </summary>
        [Required]
        public string LdapSearchFilter { get; set; }

        /// <summary>
        /// Gets or sets the ldap admin search filter.
        /// </summary>
        public string LdapAdminFilter { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether ldap admin search filter should use 'memberUid'.
        /// </summary>
        public bool EnableLdapAdminFilterMemberUid { get; set; }
    }
}
