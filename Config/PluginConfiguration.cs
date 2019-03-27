namespace Jellyfin.Plugin.LDAP_Auth
{
    public class PluginConfiguration :  MediaBrowser.Model.Plugins.BasePluginConfiguration
    {
        public string LdapServer{get;}
        public string LdapBaseDn{get;}
        public int LdapPort{get;}
        public string LdapQuery{get;}
        public string LdapBindUser{get;}
        public string LdapBindPassword{get;}
        public bool CreateUsersFromLdap{get;}
        public PluginConfiguration()
        {
            LdapServer = "ldap-server.contoso.com";
            LdapBaseDn = "o=domains,dc=contoso,dc=com";
            LdapPort = 389;
            LdapQuery = "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)";
            LdapBindUser = "CN=BindUser,DC=contoso,DC=com";
            LdapBindPassword = "password";
            CreateUsersFromLdap = true;
        }
    }
}
