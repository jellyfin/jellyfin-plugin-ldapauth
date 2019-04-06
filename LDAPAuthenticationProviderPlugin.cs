using System;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Entities;
using System.Threading.Tasks;
using Novell.Directory.Ldap;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.LDAP_Auth
{
    public class LdapAuthenticationProviderPlugin : IAuthenticationProvider
    {
        private readonly string[] _attrs = new string[]{
            "uid",
            "CN",
            "displayName"
        };
        private readonly PluginConfiguration _config;
        private readonly ILogger _logger;
        private readonly IUserManager _userManager;
        public LdapAuthenticationProviderPlugin(IUserManager userManager)
        {
            _config = Plugin.Instance.Configuration;
            _logger = Plugin.Logger;
            _userManager = userManager;
        }

        public string Name => "LDAP-Authentication";

        public bool IsEnabled => true;

        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            User user = null;    
            bool foundUser = false;
            LdapEntry ldapUser = null;        
            using (var ldapClient = new LdapConnection())
            {
                ldapClient.SecureSocketLayer = _config.UseSsl;
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
                    LdapSearchResults ldapUsers = ldapClient.Search(_config.LdapBaseDn,0,_config.LdapQuery,_attrs,false);
                    if (ldapUsers == null || ldapUsers.Count == 0)
                    {
                        _logger.LogWarning("No approved LDAP Users found from query");
                        throw new UnauthorizedAccessException("No users found in LDAP Query");
                    }
                    
                    while(ldapUsers.hasMore() && foundUser == false)
                    {
                        var currentUser = ldapUsers.next();
                        foreach(string attr in _attrs)
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
                }
            }
            
            try
            {
                user = _userManager.GetUserByName(ldapUser.getAttribute("uid").StringValue);
            }
            catch(Exception e)
            {
                _logger.LogWarning("User Manager could not find a user for LDAP User, this may not be fatal",e);
            }
            
            using (var ldapClient = new LdapConnection())
            {
                ldapClient.SecureSocketLayer = _config.UseSsl;
                try
                {
                    ldapClient.Connect(_config.LdapServer,_config.LdapPort);
                    ldapClient.Bind(ldapUser.DN,password);
                }
                catch(Exception e)
                {
                    _logger.LogError(e,"Failed to Connect or Bind to server");
                    throw e;
                }
                if(ldapClient.Bound)
                {
                    if(user == null)
                    {
                        if(_config.CreateUsersFromLdap)
                        {
                            user = await _userManager.CreateUser(ldapUser.getAttribute("uid").StringValue);
                            user.Policy.AuthenticationProviderId = GetType().Name;
                            _userManager.UpdateUserPolicy(user.Id,user.Policy);
                        }
                        else
                        {
                            _logger.LogError($"User not configured for LDAP Uid: {ldapUser.getAttribute("uid").StringValue}");
                            throw new Exception($"Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {ldapUser.getAttribute("uid").StringValue}");
                        }
                    }
                    return new ProviderAuthenticationResult
                    {
                        Username = user.Name
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
