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
                if (user.LinkedJfUserId == Guid.Empty)
                {
                    return false;
                }

                if (user.LinkedJfUserId.Equals(userGuid))
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

                if (user.LdapUid.Equals(ldapUid))
                {
                    return true;
                }

                return false;
            });
        }
    }
}
