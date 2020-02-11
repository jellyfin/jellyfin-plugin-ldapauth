namespace Jellyfin.Plugin.LDAP_Auth
{
    public class PluginConfiguration :  MediaBrowser.Model.Plugins.BasePluginConfiguration
    {
        public string LdapServer { get; set; }
        public string LdapBaseDn { get; set; }
        public int LdapPort { get; set; }
        public string LdapSearchAttributes { get; set; }
        public string LdapUsernameAttribute { get; set; }
        public string LdapSearchFilter { get; set; }
        public string LdapAdminFilter { get; set; }
        public string LdapBindUser { get; set; }
        public string LdapBindPassword { get; set; }
        public bool CreateUsersFromLdap { get; set; }
        public bool UseSsl { get; set; }
        public string EasyPasswordField { get; set; }
        public PluginConfiguration()
        {
            LdapServer = "ldap-server.contoso.com";
            LdapBaseDn = "o=domains,dc=contoso,dc=com";
            LdapPort = 389;
            LdapSearchAttributes = "uid, cn, mail, displayName";
            LdapUsernameAttribute = "uid";
            LdapSearchFilter = "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)";
            LdapAdminFilter = "(enabledService=JellyfinAdministrator)";
            LdapBindUser = "CN=BindUser,DC=contoso,DC=com";
            LdapBindPassword = "password";
            EasyPasswordField = string.Empty;
            CreateUsersFromLdap = true;
            UseSsl = true;
        }
    }
}
