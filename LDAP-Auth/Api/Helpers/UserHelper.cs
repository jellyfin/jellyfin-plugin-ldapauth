using System;
using System.Linq;
using Jellyfin.Plugin.LDAP_Auth.Api.Models;

namespace Jellyfin.Plugin.LDAP_Auth.Api.Helpers
{
    internal static class UserHelper
    {
        public static LdapUser GetLdapUser(Guid userGuid)
        {
            var ldapUsers = LdapPlugin.Instance.Configuration.GetAllLdapUsers();
            if (ldapUsers.Count == 0)
            {
                return null;
            }

            return ldapUsers.FirstOrDefault(user =>
            {
                if (user.LinkedJellyfinUserId == Guid.Empty)
                {
                    return false;
                }

                if (user.LinkedJellyfinUserId.Equals(userGuid))
                {
                    return true;
                }

                return false;
            });
        }

        public static LdapUser GetLdapUser(string ldapUid)
        {
            var ldapUsers = LdapPlugin.Instance.Configuration.GetAllLdapUsers();
            if (ldapUsers.Count == 0)
            {
                return null;
            }

            return ldapUsers.FirstOrDefault(user =>
            {
                if (string.IsNullOrEmpty(user.LdapUid))
                {
                    return false;
                }

                if (string.Equals(user.LdapUid, ldapUid, StringComparison.Ordinal))
                {
                    return true;
                }

                return false;
            });
        }
    }
}
