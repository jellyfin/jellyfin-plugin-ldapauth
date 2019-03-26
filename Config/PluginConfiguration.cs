using System.Collections.Generic;
namespace Jellyfin.Plugin.LDAP_Auth
{
    public class PluginConfiguration :  MediaBrowser.Model.Plugins.BasePluginConfiguration
    {
        public string LDAPServer{get;}
        public string LDAPBaseDN{get;}
        public int LDAPPort{get;}
        public string LDAPQuery{get;}
        public string LDAPBindUser{get;}
        public string LDAPBindPassword{get;}
        public bool CreateUsersFromLDAP{get;}
        public PluginConfiguration()
        {
            LDAPServer = "ldap-server.contoso.com";
            LDAPBaseDN = "o=domains,dc=contoso,dc=com";
            LDAPPort = 389;
            LDAPQuery = "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)";
            LDAPBindUser = "CN=BindUser,DC=contoso,DC=com";
            LDAPBindPassword = "password";
            CreateUsersFromLDAP = true;
        }
    }
}