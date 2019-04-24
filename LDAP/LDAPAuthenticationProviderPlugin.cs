using System;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Entities;
using System.Threading.Tasks;
using Novell.Directory.Ldap;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.LDAP
{
    public class LdapAuthenticationProviderPlugin : IAuthenticationProvider
    {
        private readonly PluginConfiguration _config;
        private readonly ILogger _logger;
        private readonly IUserManager _userManager;
        public LdapAuthenticationProviderPlugin(IUserManager userManager)
        {
            _config = Plugin.Instance.Configuration;
            _logger = Plugin.Logger;
            _userManager = userManager;
        }

        private string[] ldapAttrs => _config.LdapSearchAttributes.Replace(" ", "").Split(',');
        private string usernameAttr => _config.LdapUsernameAttribute;
        private string searchFilter => _config.LdapSearchFilter;
        private string adminFilter => _config.LdapAdminFilter;

        public string Name => "LDAP";

        public bool IsEnabled => true;

        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            User user = null;    
            bool foundUser = false;
            LdapEntry ldapUser = null;        
            using (var ldapClient = new LdapConnection() { SecureSocketLayer = _config.UseSsl })
            {
                try
                {
                    ldapClient.Connect(_config.LdapServer,_config.LdapPort);
                    ldapClient.Bind(_config.LdapBindUser,_config.LdapBindPassword);
                }
                catch(Exception e)
                {
                    _logger.LogError(e,"Failed to Connect or Bind to server");
                    throw e;
                }
                if(ldapClient.Bound)
                {
                    LdapSearchResults ldapUsers = ldapClient.Search(_config.LdapBaseDn, 2, searchFilter, ldapAttrs, false);
                    if (ldapUsers == null)
                    {
                        _logger.LogWarning("No LDAP users found from query");
                        throw new UnauthorizedAccessException("No users found in LDAP Query");
                    }
                    _logger.LogDebug("Search: {1} {2} @ {3}", _config.LdapBaseDn, searchFilter, _config.LdapServer);
                   
                    while(ldapUsers.hasMore() && foundUser == false)
                    {
                        var currentUser = ldapUsers.next();
                        foreach(string attr in ldapAttrs)
                        {
                            var toCheck = currentUser.getAttribute(attr);
                            if(toCheck?.StringValueArray != null)
                            {
                                foreach (string name in toCheck.StringValueArray)
                                {
                                    if(username == name)
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
            }
            
            string ldap_username = ldapUser.getAttribute(usernameAttr).StringValue;
            _logger.LogDebug("Setting username: {1}", ldap_username);

            try
            {
                user = _userManager.GetUserByName(ldap_username);
            }
            catch(Exception e)
            {
                _logger.LogWarning("User Manager could not find a user for LDAP User, this may not be fatal",e);
            }

            using (var ldapClient = new LdapConnection() { SecureSocketLayer = _config.UseSsl })
            {
                _logger.LogDebug("Trying bind as user {1}", ldapUser.DN);
                try
                {
                    ldapClient.Connect(_config.LdapServer, _config.LdapPort);
                    ldapClient.Bind(ldapUser.DN, password);
                }
                catch(Exception e)
                {
                    _logger.LogError(e,"Failed to Connect or Bind to server as user {1}", ldapUser.DN);
                    throw e;
                }
                if(ldapClient.Bound)
                {
                    if(user == null)
                    {
                        // Determine if the user should be an administrator
                        bool ldap_isAdmin = false;
                        // Search the current user DN with the adminFilter
                        LdapSearchResults ldapUsers = ldapClient.Search(ldapUser.DN, 0, adminFilter, ldapAttrs, false);
                        var hasMore = ldapUsers.hasMore();
                        // If we got non-zero, then the filter matched and the user is an admin
                        if(ldapUsers.Count != 0)
                        {
                            ldap_isAdmin = true;
                        }

                        _logger.LogDebug("Creating new user {1} - is admin? {2}", ldap_username, ldap_isAdmin);
                        if(_config.CreateUsersFromLdap)
                        {
                            user = await _userManager.CreateUser(ldap_username);
                            user.Policy.AuthenticationProviderId = GetType().Name;
                            user.Policy.IsAdministrator = ldap_isAdmin;
                            _userManager.UpdateUserPolicy(user.Id, user.Policy);
                        }
                        else
                        {
                            _logger.LogError($"User not configured for LDAP Uid: {ldap_username}");
                            throw new Exception($"Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {ldap_username}");
                        }
                    }
                    return new ProviderAuthenticationResult
                    {
                        Username = ldap_username
                    };
                }
                else
                {
                    _logger.LogError("Error logging in, invalid LDAP username or password");
                    throw new Exception("Error completing LDAP login. Invalid username or password.");
                }
            }
        }

        public Task ChangePassword(User user, string newPassword)
        {
            throw new NotImplementedException("Changing LDAP passwords currently unsupported");
        }

        public Task<bool> HasPassword(User user)
        {
            return Task.FromResult(true);
        }
    }
}
