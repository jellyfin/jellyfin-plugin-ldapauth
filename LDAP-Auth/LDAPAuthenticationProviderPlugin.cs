using System;
using System.Linq;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Entities;
using System.Threading.Tasks;
using MediaBrowser.Common;
using MediaBrowser.Common.Cryptography;
using MediaBrowser.Model.Cryptography;
using Novell.Directory.Ldap;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.LDAP_Auth
{
    public class LdapAuthenticationProviderPlugin : IAuthenticationProvider
    {
        private readonly PluginConfiguration _config;
        private readonly ILogger _logger;
        private readonly IUserManager _userManager;
        private readonly ICryptoProvider _cryptoProvider;

        public LdapAuthenticationProviderPlugin(IUserManager userManager, ICryptoProvider cryptoProvider)
        {
            _config = Plugin.Instance.Configuration;
            _logger = Plugin.Logger;
            _userManager = userManager;
            _cryptoProvider = cryptoProvider;
        }

        private string[] ldapUsernameAttributes => _config.LdapSearchAttributes.Replace(" ", string.Empty).Split(',');

        private string[] ldapAttributes => ldapUsernameAttributes.Append(easyPasswordAttr).ToArray();

        private string usernameAttr => _config.LdapUsernameAttribute;
        private string searchFilter => _config.LdapSearchFilter;
        private string adminFilter => _config.LdapAdminFilter;
        private string easyPasswordAttr => _config.EasyPasswordField;
        private const string passwordAttr = "userPassword";

        public string Name => "LDAP-Authentication";

        public bool IsEnabled => true;

        private LdapEntry LocateLdapUser(string username)
        {
            bool foundUser = false;
            LdapEntry ldapUser = null;
            using (var ldapClient = new LdapConnection {SecureSocketLayer = _config.UseSsl})
            {
                try
                {
                    if (_config.SkipSslVerify)
                    {
                        ldapClient.UserDefinedServerCertValidationDelegate +=
                            LdapClient_UserDefinedServerCertValidationDelegate;
                    }

                    ldapClient.Connect(_config.LdapServer, _config.LdapPort);
                    if (_config.UseStartTls)
                        ldapClient.StartTls();

                    ldapClient.Bind(_config.LdapBindUser, _config.LdapBindPassword);
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to Connect or Bind to server");
                    throw;
                }
                finally
                {
                    ldapClient.UserDefinedServerCertValidationDelegate -= LdapClient_UserDefinedServerCertValidationDelegate;
                }

                if (!ldapClient.Bound)
                    return null;

                var ldapUsers =
                    ldapClient.Search(_config.LdapBaseDn, 2, searchFilter, ldapAttributes, false);
                if (ldapUsers == null)
                {
                    _logger.LogWarning("No LDAP users found from query");
                    throw new UnauthorizedAccessException("No users found in LDAP Query");
                }

                _logger.LogDebug("Search: {1} {2} @ {3}", _config.LdapBaseDn, searchFilter, _config.LdapServer);

                while (ldapUsers.HasMore() && foundUser == false)
                {
                    var currentUser = ldapUsers.Next();
                    foreach (string attr in ldapUsernameAttributes)
                    {
                        var toCheck = GetAttribute(currentUser, attr);
                        if (toCheck?.StringValueArray != null)
                        {
                            foreach (string name in toCheck.StringValueArray)
                            {
                                if (username == name)
                                {
                                    ldapUser = currentUser;
                                    foundUser = true;
                                }
                            }
                        }
                    }
                }

                if (foundUser == false)
                {
                    _logger.LogError("Found no users matching {1} in LDAP search.", username);
                    throw new Exception("Found no LDAP users matching provided username.");
                }
            }

            return ldapUser;
        }

        private void SetAttribute(LdapEntry userEntry, string attr, string attrValue)
        {
            using (var ldapClient = new LdapConnection {SecureSocketLayer = _config.UseSsl})
            {
                try
                {
                    if (_config.SkipSslVerify)
                    {
                        ldapClient.UserDefinedServerCertValidationDelegate +=
                            LdapClient_UserDefinedServerCertValidationDelegate;
                    }

                    ldapClient.Connect(_config.LdapServer, _config.LdapPort);
                    if (_config.UseStartTls)
                        ldapClient.StartTls();

                    ldapClient.Bind(_config.LdapBindUser, _config.LdapBindPassword);
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to Connect or Bind to server");
                    throw;
                }
                finally
                {
                    ldapClient.UserDefinedServerCertValidationDelegate -= LdapClient_UserDefinedServerCertValidationDelegate;
                }

                var existingAttr = GetAttribute(userEntry, attr);
                var ldapModType = existingAttr == null ? LdapModification.Add : LdapModification.Replace;
                var modification = new LdapModification(
                    ldapModType,
                    new LdapAttribute(attr, attrValue ?? string.Empty)
                );

                ldapClient.Modify(userEntry.Dn, modification);
            }
        }

        private LdapAttribute GetAttribute(LdapEntry userEntry, string attr)
        {
            try
            {
                return userEntry.GetAttribute(attr);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Error getting LDAP attribute");
                return null;
            }
        }

        public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            User user = null;
            LdapEntry ldapUser = LocateLdapUser(username);

            string ldapUsername = GetAttribute(ldapUser, usernameAttr)?.StringValue;
            _logger.LogDebug("Setting username: {1}", ldapUsername);

            try
            {
                user = _userManager.GetUserByName(ldapUsername);
            }
            catch (Exception e)
            {
                _logger.LogWarning("User Manager could not find a user for LDAP User, this may not be fatal", e);
            }

            using (var ldapClient = new LdapConnection {SecureSocketLayer = _config.UseSsl})
            {
                _logger.LogDebug("Trying bind as user {1}", ldapUser.Dn);
                try
                {
                    ldapClient.Connect(_config.LdapServer, _config.LdapPort);
                    ldapClient.Bind(ldapUser.Dn, password);
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to Connect or Bind to server as user {1}", ldapUser.Dn);
                    throw;
                }

                if (ldapClient.Bound)
                {
                    if (user == null)
                    {
                        // Determine if the user should be an administrator
                        bool ldapIsAdmin = false;
                        // Search the current user DN with the adminFilter
                        var ldapUsers = ldapClient.Search(ldapUser.Dn, 0, adminFilter, ldapUsernameAttributes, false);

                        // If we got non-zero, then the filter matched and the user is an admin
                        if (ldapUsers.Count != 0)
                        {
                            ldapIsAdmin = true;
                        }

                        _logger.LogDebug("Creating new user {1} - is admin? {2}", ldapUsername, ldapIsAdmin);
                        if (_config.CreateUsersFromLdap)
                        {
                            user = _userManager.CreateUser(ldapUsername);
                            user.Policy.AuthenticationProviderId = GetType().Name;
                            user.Policy.IsAdministrator = ldapIsAdmin;
                            _userManager.UpdateUserPolicy(user.Id, user.Policy);
                        }
                        else
                        {
                            _logger.LogError($"User not configured for LDAP Uid: {ldapUsername}");
                            throw new Exception(
                                $"Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {ldapUsername}");
                        }
                    }

                    return Task.FromResult(new ProviderAuthenticationResult {Username = ldapUsername});
                }
                else
                {
                    _logger.LogError("Error logging in, invalid LDAP username or password");
                    throw new Exception("Error completing LDAP login. Invalid username or password.");
                }
            }
        }

        public bool HasPassword(User user)
        {
            return true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        /// <inheritdoc/>
        public string GetEasyPasswordHash(User user)
        {
            if (string.IsNullOrEmpty(easyPasswordAttr))
            {
                return string.Empty;
            }

            var ldapUser = LocateLdapUser(user.Name);
            var hash = GetAttribute(ldapUser, easyPasswordAttr)?.StringValue;
            return string.IsNullOrEmpty(hash)
                ? null
                : hash;
        }

        public Task ChangePassword(User user, string newPassword)
        {

            var ldapUser = LocateLdapUser(user.Name);
            if (ldapUser == null)
                return Task.FromException(new Exception());

            var hashString = CreateHash(newPassword);
            SetAttribute(ldapUser, passwordAttr, hashString);
            return Task.CompletedTask;
        }

        public void ChangeEasyPassword(User user, string newPassword, string _)
        {
            if (string.IsNullOrEmpty(easyPasswordAttr))
            {
                throw new ApplicationException("Must configure EasyPassword field");
            }

            var ldapUser = LocateLdapUser(user.Name);
            if (ldapUser == null)
                return;

            var hashString = CreateHash(newPassword);
            SetAttribute(ldapUser, easyPasswordAttr, hashString);
        }

        private string CreateHash(string input)
        {
            {
                // LDAP can't store NULL as value, so store empty string
                string hashString;
                if (string.IsNullOrEmpty(input))
                    hashString = string.Empty;
                else
                {
                    PasswordHash hash = _cryptoProvider.CreatePasswordHash(input);
                    hashString = hash.ToString();
                }

                return hashString;
            }
        }

        private static bool LdapClient_UserDefinedServerCertValidationDelegate(
            object sender,
            System.Security.Cryptography.X509Certificates.X509Certificate certificate,
            System.Security.Cryptography.X509Certificates.X509Chain chain,
            System.Net.Security.SslPolicyErrors sslPolicyErrors)
            => true;
    }
}
