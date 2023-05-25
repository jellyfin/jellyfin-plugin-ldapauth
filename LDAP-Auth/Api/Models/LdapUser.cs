using System;

namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// LdapUser class.
    /// </summary>
    public class LdapUser
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LdapUser"/> class.
        /// </summary>
        public LdapUser()
        {
            LinkedJfUserId = Guid.Empty;
            LdapUid = string.Empty;
        }

        /// <summary>
        /// Gets or sets the linked Jellyfin user id.
        /// </summary>
        public Guid LinkedJfUserId { get; set; }

        /// <summary>
        /// Gets or sets the LDAP Uid associated with the user.
        /// </summary>
        public string LdapUid { get; set; }
    }
}
