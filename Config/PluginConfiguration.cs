namespace Jellyfin.Plugin.LDAP_Auth
{
    public class PluginConfiguration :  MediaBrowser.Model.Plugins.BasePluginConfiguration
    {
        public string LdapServer{get; set; }
        public string LdapBaseDn{get; set; }
        public int LdapPort{get; set; }
        public string LdapQuery{get; set; }
        public string LdapBindUser{get; set; }
        public string LdapBindPassword{get; set; }
        public bool CreateUsersFromLdap{get; set; }
        public bool UseSsl { get; set; }
        public PluginConfiguration()
        {
            LdapServer = "ldap-server.contoso.com";
            LdapBaseDn = "o=domains,dc=contoso,dc=com";
            LdapPort = 389;
            LdapQuery = "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)";
            LdapBindUser = "CN=BindUser,DC=contoso,DC=com";
            LdapBindPassword = "password";
            CreateUsersFromLdap = true;
            UseSsl = true;
        }
    }
}
