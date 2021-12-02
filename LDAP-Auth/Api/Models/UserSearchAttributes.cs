using System.ComponentModel.DataAnnotations;
using Jellyfin.Plugin.LDAP_Auth.Config;

namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// A subset of <see cref="PluginConfiguration"/> containing just the settings for searching for users,
    /// as well as an optional string to test the search with.
    /// </summary>
    public class UserSearchAttributes
    {
        /// <summary>
        /// Gets or sets the ldap search attributes.
        /// </summary>
        [Required]
        public string LdapSearchAttributes { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to use case insensitive username comparison.
        /// </summary>
        public bool EnableCaseInsensitiveUsername { get; set; }

        /// <summary>
        /// Gets or sets the username to search for as a test.
        /// </summary>
        public string TestSearchUsername { get; set; }
    }
}
