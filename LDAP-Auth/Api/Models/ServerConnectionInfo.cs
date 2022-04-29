using System.ComponentModel.DataAnnotations;
using Jellyfin.Plugin.LDAP_Auth.Config;

namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// A subset of <see cref="PluginConfiguration"/> containing just the settings for connecting and binding to the server.
    /// </summary>
    public class ServerConnectionInfo
    {
        /// <summary>
        /// Gets or sets the ldap host.
        /// </summary>
        [Required]
        public string LdapServer { get; set; }

        /// <summary>
        /// Gets or sets the ldap port.
        /// </summary>
        [Required]
        public int LdapPort { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether ssl should be used.
        /// </summary>
        [Required]
        public bool UseSsl { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether start tls should be used.
        /// </summary>
        [Required]
        public bool UseStartTls { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether ssl verification should be skipped.
        /// </summary>
        [Required]
        public bool SkipSslVerify { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to allow password reset flow.
        /// </summary>
        [Required]
        public bool AllowPassChange { get; set; }

        /// <summary>
        /// Gets or sets the ldap bind user.
        /// </summary>
        public string LdapBindUser { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the ldap bind password.
        /// </summary>
        public string LdapBindPassword { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the ldap base search dn.
        /// </summary>
        [Required]
        public string LdapBaseDn { get; set; }

        /// <summary>
        /// Gets or sets the password reset url.
        /// </summary>
        public string PasswordResetUrl { get; set; }
    }
}
