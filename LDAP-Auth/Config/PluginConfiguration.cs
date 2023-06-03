using System;
using System.Collections.Generic;
using System.Linq;

using Jellyfin.Plugin.LDAP_Auth.Api.Models;

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
            LdapPort = 389;
            AllowPassChange = false;
            UseSsl = true;
            UseStartTls = false;
            SkipSslVerify = false;
            LdapBindUser = "CN=BindUser,DC=contoso,DC=com";
            LdapBindPassword = "password";
            LdapBaseDn = "o=domains,dc=contoso,dc=com";
            LdapSearchFilter = "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)";
            LdapAdminBaseDn = string.Empty;
            LdapAdminFilter = "(enabledService=JellyfinAdministrator)";
            EnableLdapAdminFilterMemberUid = false;
            LdapSearchAttributes = "uid, cn, mail, displayName";
            LdapClientCertPath = string.Empty;
            LdapClientKeyPath = string.Empty;
            LdapRootCaPath = string.Empty;
            CreateUsersFromLdap = true;
            LdapUidAttribute = "uid";
            LdapUsernameAttribute = "cn";
            LdapPasswordAttribute = "userPassword";
            EnableAllFolders = false;
            EnabledFolders = Array.Empty<string>();

            LdapUsers = Array.Empty<LdapUser>();
        }

        /// <summary>
        /// Gets or sets the ldap users.
        /// </summary>
        public LdapUser[] LdapUsers { get; set; }

        /// <summary>
        /// Gets or sets the ldap server ip or url.
        /// </summary>
        public string LdapServer { get; set; }

        /// <summary>
        /// Gets or sets the ldap port.
        /// </summary>
        public int LdapPort { get; set; }

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
        /// Gets or sets the ldap bind user dn.
        /// </summary>
        public string LdapBindUser { get; set; }

        /// <summary>
        /// Gets or sets the ldap bind user password.
        /// </summary>
        public string LdapBindPassword { get; set; }

        /// <summary>
        /// Gets or sets the ldap base search dn.
        /// </summary>
        public string LdapBaseDn { get; set; }

        /// <summary>
        /// Gets or sets the ldap user search filter.
        /// </summary>
        public string LdapSearchFilter { get; set; }

        /// <summary>
        /// Gets or sets the ldap admin search base dn.
        /// </summary>
        public string LdapAdminBaseDn { get; set; }

        /// <summary>
        /// Gets or sets the ldap admin search filter.
        /// </summary>
        public string LdapAdminFilter { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable admin filter based on memberUid.
        /// </summary>
        public bool EnableLdapAdminFilterMemberUid { get; set; }

        /// <summary>
        /// Gets or sets the ldap search attributes.
        /// </summary>
        public string LdapSearchAttributes { get; set; }

        /// <summary>
        /// Gets or sets the ldap client cert path.
        /// </summary>
        public string LdapClientCertPath { get; set; }

        /// <summary>
        /// Gets or sets the ldap client cert path.
        /// </summary>
        public string LdapClientKeyPath { get; set; }

        /// <summary>
        /// Gets or sets the ldap root CA path.
        /// </summary>
        public string LdapRootCaPath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to create Jellyfin users from ldap.
        /// </summary>
        public bool CreateUsersFromLdap { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to allow password change (Requires privileged bind user).
        /// </summary>
        public bool AllowPassChange { get; set; }

        /// <summary>
        /// Gets or sets the ldap uid attribute.
        /// </summary>
        public string LdapUidAttribute { get; set; }

        /// <summary>
        /// Gets or sets the ldap username attribute.
        /// </summary>
        public string LdapUsernameAttribute { get; set; }

        /// <summary>
        /// Gets or sets the ldap password attribute.
        /// </summary>
        public string LdapPasswordAttribute { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable access to all library folders.
        /// </summary>
        public bool EnableAllFolders { get; set; }

        /// <summary>
        /// Gets or sets a list of folder Ids which are enabled for access by default.
        /// </summary>
        public string[] EnabledFolders { get; set; }

        /// <summary>
        /// Gets or sets the password reset url.
        /// </summary>
        public string PasswordResetUrl { get; set; }

        /// <summary>
        /// Adds a user to the ldap users.
        /// </summary>
        /// <param name="userGuid">The user Guid.</param>
        /// <param name="ldapUid">The LDAP UID associated with the user.</param>
        public void AddUser(Guid userGuid, string ldapUid)
        {
            // Ensure we do not have more than one entry for a given user
            // This may happen if a user tries to authenticate after their
            // ldapUid has changed or if their Jellyfin account has been deleted
            RemoveUser(userGuid);
            RemoveUser(ldapUid);

            var ldapUsers = LdapUsers.ToList();
            var ldapUser = new LdapUser
            {
                LinkedJfUserId = userGuid,
                LdapUid = ldapUid
            };
            ldapUsers.Add(ldapUser);
            LdapUsers = ldapUsers.ToArray();
        }

        /// <summary>
        /// Removes a user from the LDAP users.
        /// </summary>
        /// <param name="userGuid">The user id.</param>
        public void RemoveUser(Guid userGuid)
        {
            LdapUsers = LdapUsers.Where(user => user.LinkedJfUserId != userGuid).ToArray();
        }

        /// <summary>
        /// Removes a user from the LDAP users.
        /// </summary>
        /// <param name="ldapUid">The LDAP uid of the user.</param>
        public void RemoveUser(string ldapUid)
        {
            var ldapUsers = LdapUsers.ToList();
            ldapUsers.RemoveAll(user => user.LdapUid == ldapUid);
            LdapUsers = ldapUsers.ToArray();
        }

        /// <summary>
        /// Gets a list of all LDAP users.
        /// </summary>
        /// <returns>IReadonlyList{LdapUser} with all LDAP users.</returns>
        public IReadOnlyList<LdapUser> GetAllLdapUsers()
        {
            return LdapUsers.ToList();
        }
    }
}
