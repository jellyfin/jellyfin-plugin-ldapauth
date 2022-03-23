namespace Jellyfin.Plugin.LDAP_Auth.Config
{
    /// <summary>
    /// Plugin Configuration.
    /// </summary>
    public class PluginConfiguration : MediaBrowser.Model.Plugins.BasePluginConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
        /// </summary>
        public PluginConfiguration()
        {
            LdapServer = "ldap-server.contoso.com";
            LdapBaseDn = "o=domains,dc=contoso,dc=com";
            LdapPort = 389;
            LdapSearchAttributes = "uid, cn, mail, displayName";
            LdapUsernameAttribute = "uid";
            LdapSearchFilter = "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)";
            LdapAdminFilter = "(enabledService=JellyfinAdministrator)";
            LdapAdminBaseDn = string.Empty;
            LdapBindUser = "CN=BindUser,DC=contoso,DC=com";
            LdapBindPassword = "password";
            CreateUsersFromLdap = true;
            UseSsl = true;
            UseStartTls = false;
            SkipSslVerify = false;
            EnableCaseInsensitiveUsername = false;
        }

        /// <summary>
        /// Gets or sets the ldap server ip or url.
        /// </summary>
        public string LdapServer { get; set; }

        /// <summary>
        /// Gets or sets the ldap base search dn.
        /// </summary>
        public string LdapBaseDn { get; set; }

        /// <summary>
        /// Gets or sets the ldap port.
        /// </summary>
        public int LdapPort { get; set; }

        /// <summary>
        /// Gets or sets the ldap search attributes.
        /// </summary>
        public string LdapSearchAttributes { get; set; }

        /// <summary>
        /// Gets or sets the ldap username attribute.
        /// </summary>
        public string LdapUsernameAttribute { get; set; }

        /// <summary>
        /// Gets or sets the ldap user search filter.
        /// </summary>
        public string LdapSearchFilter { get; set; }

        /// <summary>
        /// Gets or sets the ldap admin search filter.
        /// </summary>
        public string LdapAdminFilter { get; set; }

        /// <summary>
        /// Gets or sets the ldap admin search base dn.
        /// </summary>
        public string LdapAdminBaseDn { get; set; }

        /// <summary>
        /// Gets or sets the ldap bind user dn.
        /// </summary>
        public string LdapBindUser { get; set; }

        /// <summary>
        /// Gets or sets the ldap bind user password.
        /// </summary>
        public string LdapBindPassword { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to create Jellyfin users from ldap.
        /// </summary>
        public bool CreateUsersFromLdap { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to use ssl when connecting to the ldap server.
        /// </summary>
        public bool UseSsl { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to use StartTls when connecting to the ldap server.
        /// </summary>
        public bool UseStartTls { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to skip ssl verification.
        /// </summary>
        public bool SkipSslVerify { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to use case insensitive username comparison.
        /// </summary>
        public bool EnableCaseInsensitiveUsername { get; set; }
    }
}
