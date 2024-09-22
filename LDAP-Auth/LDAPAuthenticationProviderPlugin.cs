using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using Jellyfin.Plugin.LDAP_Auth.Api.Helpers;
using Jellyfin.Plugin.LDAP_Auth.Api.Models;
using Jellyfin.Plugin.LDAP_Auth.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Model.Users;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;

namespace Jellyfin.Plugin.LDAP_Auth
{
    /// <summary>
    /// Ldap Authentication Provider Plugin.
    /// </summary>
    public class LdapAuthenticationProviderPlugin : IAuthenticationProvider, IPasswordResetProvider
    {
        private readonly ILogger<LdapAuthenticationProviderPlugin> _logger;
        private readonly IApplicationHost _applicationHost;

        /// <summary>
        /// Initializes a new instance of the <see cref="LdapAuthenticationProviderPlugin"/> class.
        /// </summary>
        /// <param name="applicationHost">Instance of the <see cref="IApplicationHost"/> interface.</param>
        /// <param name="logger">Instance of the <see cref="ILogger{LdapAuthenticationProviderPlugin}"/> interface.</param>
        public LdapAuthenticationProviderPlugin(IApplicationHost applicationHost, ILogger<LdapAuthenticationProviderPlugin> logger)
        {
            _logger = logger;
            _applicationHost = applicationHost;
        }

        private string[] LdapUsernameAttributes => LdapPlugin.Instance.Configuration.LdapSearchAttributes.Replace(" ", string.Empty, StringComparison.Ordinal).Split(',');

        private string UidAttr => LdapPlugin.Instance.Configuration.LdapUidAttribute;

        private string UsernameAttr => LdapPlugin.Instance.Configuration.LdapUsernameAttribute;

        private bool EnableProfileImageSync => LdapPlugin.Instance.Configuration.EnableLdapProfileImageSync;

        private string ProfileImageAttr => LdapPlugin.Instance.Configuration.LdapProfileImageAttribute;

        private string SearchFilter => LdapPlugin.Instance.Configuration.LdapSearchFilter;

        private string AdminFilter => LdapPlugin.Instance.Configuration.LdapAdminFilter;

        private bool EnableAdminFilterMemberUid => LdapPlugin.Instance.Configuration.EnableLdapAdminFilterMemberUid;

        /// <summary>
        /// Gets plugin name.
        /// </summary>
        public string Name => "LDAP-Authentication";

        /// <summary>
        /// Gets a value indicating whether gets plugin enabled.
        /// </summary>
        public bool IsEnabled => true;

        /// <summary>
        /// Authenticate user against the ldap server.
        /// </summary>
        /// <param name="username">Username to authenticate.</param>
        /// <param name="password">Password to authenticate.</param>
        /// <returns>A <see cref="ProviderAuthenticationResult"/> with the authentication result.</returns>
        /// <exception cref="AuthenticationException">Exception when failing to authenticate.</exception>
        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            var userManager = _applicationHost.Resolve<IUserManager>();
            User user = null;
            var ldapUser = LocateLdapUser(username);
            var ldapUid = GetAttribute(ldapUser, UidAttr)?.StringValue;
            _logger.LogDebug("Got ldapUid: {LdapUid}", ldapUid);
            var ldapUsername = GetAttribute(ldapUser, UsernameAttr)?.StringValue;
            _logger.LogDebug("Got ldapUsername: {LdapUsername}", ldapUsername);
            try
            {
                user = userManager.GetUserById(UserHelper.GetLdapUser(ldapUid).LinkedJellyfinUserId);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "User Manager could not find an user with such ldapUid, this may not be fatal");
            }

            if (user == null)
            {
                // Try to lookup the user by the ldapUsername in case it
                // does not exist in the plugin config lookup table or the
                // ldapUid has changed for some reason.
                //
                // XXX: This is not a foolproof solution. If both ldapUid and
                // ldapUsername have changed since last login, the user will
                // be treated as a new user.
                try
                {
                    user = userManager.GetUserByName(ldapUsername);
                    if (!string.Equals(user.AuthenticationProviderId, GetType().FullName!, StringComparison.OrdinalIgnoreCase))
                    {
                        // This user is not managed by us, ignore it
                        user = null;
                    }
                    else
                    {
                        // Add the user to our Ldap users
                        LdapPlugin.Instance.Configuration.AddUser(user.Id, ldapUid, string.Empty);
                        LdapPlugin.Instance.SaveConfiguration();
                    }
                }
                catch (Exception e)
                {
                    _logger.LogWarning(e, "User Manager could not find an user with such ldapUsername, this may not be fatal");
                }
            }

            using (var currentUserConnection = ConnectToLdap(ldapUser.Dn, password))
            {
                if (!currentUserConnection.Bound)
                {
                    _logger.LogError("Error logging in, invalid LDAP username or password");
                    throw new AuthenticationException("Error completing LDAP login. Invalid username or password.");
                }
            }

            // Determine if the user should be an administrator
            var ldapIsAdmin = false;

            if (!string.IsNullOrEmpty(AdminFilter) && !string.Equals(AdminFilter, "_disabled_", StringComparison.Ordinal))
            {
                using var ldapClient = ConnectToLdap();

                ldapClient.Constraints = GetSearchConstraints(
                    ldapClient,
                    LdapPlugin.Instance.Configuration.LdapBindUser,
                    LdapPlugin.Instance.Configuration.LdapBindPassword);

                try
                {
                    var adminBaseDn = LdapPlugin.Instance.Configuration.LdapAdminBaseDn;
                    if (string.IsNullOrEmpty(adminBaseDn))
                    {
                        adminBaseDn = LdapPlugin.Instance.Configuration.LdapBaseDn;
                    }

                    var ldapUsers = ldapClient.Search(
                        adminBaseDn,
                        LdapConnection.ScopeSub,
                        AdminFilter.Replace("{username}", LdapUtils.SanitizeFilter(username), StringComparison.OrdinalIgnoreCase),
                        Array.Empty<string>(),
                        false);

                    if (EnableAdminFilterMemberUid)
                    {
                        ldapIsAdmin = ldapUsers.HasMore();
                    }
                    else
                    {
                        var foundUser = false;
                        while (ldapUsers.HasMore() && !foundUser)
                        {
                            var currentUser = ldapUsers.Next();
                            if (string.Equals(ldapUser.Dn, currentUser.Dn, StringComparison.Ordinal))
                            {
                                ldapIsAdmin = true;
                                foundUser = true;
                            }
                        }
                    }
                }
                catch (LdapException e)
                {
                    _logger.LogError(e, "Failed to check for admin with: {Filter}", SearchFilter);
                    throw new AuthenticationException("Error completing LDAP login while applying admin filter.");
                }
            }

            if (user == null)
            {
                _logger.LogDebug("Creating new user {Username} - is admin? {IsAdmin}", ldapUsername, ldapIsAdmin);
                if (LdapPlugin.Instance.Configuration.CreateUsersFromLdap)
                {
                    user = await userManager.CreateUserAsync(ldapUsername).ConfigureAwait(false);
                    var providerName = GetType().FullName!;
                    user.AuthenticationProviderId = providerName;
                    user.PasswordResetProviderId = providerName;
                    user.SetPermission(PermissionKind.IsAdministrator, ldapIsAdmin);
                    user.SetPermission(PermissionKind.EnableAllFolders, LdapPlugin.Instance.Configuration.EnableAllFolders);
                    if (!LdapPlugin.Instance.Configuration.EnableAllFolders)
                    {
                        user.SetPreference(PreferenceKind.EnabledFolders, LdapPlugin.Instance.Configuration.EnabledFolders);
                    }

                    var providerManager = _applicationHost.Resolve<IProviderManager>();
                    var serverConfigurationManager = _applicationHost.Resolve<IServerConfigurationManager>();
                    var ldapProfileImage = Convert.FromBase64String(GetAttribute(ldapUser, ProfileImageAttr).StringValue);
                    var ldapProfileImageHash = string.Empty;
                    if (ldapProfileImage is not null && EnableProfileImageSync)
                    {
                        ldapProfileImageHash = Convert.ToBase64String(MD5.HashData(ldapProfileImage));

                        await ProfileImageUpdater.SetProfileImage(user, ldapProfileImage, serverConfigurationManager, providerManager).ConfigureAwait(false);
                    }

                    await userManager.UpdateUserAsync(user).ConfigureAwait(false);

                    // Add the user to our Ldap users
                    LdapPlugin.Instance.Configuration.AddUser(user.Id, ldapUid, ldapProfileImageHash);
                    LdapPlugin.Instance.SaveConfiguration();
                }
                else
                {
                    _logger.LogError("User not configured for LDAP Uid: {LdapUsername}", ldapUsername);
                    throw new AuthenticationException(
                        $"Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {ldapUsername}");
                }
            }
            else
            {
                var userNeedsUpdate = false;

                // User exists; if needed update its username
                if (!string.Equals(user.Username, ldapUsername, StringComparison.Ordinal))
                {
                    _logger.LogDebug("Updating user {Username} username to: {LdapUsername}.", user.Username, ldapUsername);
                    // userManager will take care of saving the new name to DB
                    // no need to do it ourselves
                    await userManager.RenameUser(user, ldapUsername);
                }

                // User exists; if the admin has enabled an AdminFilter, check if the user's
                // 'IsAdministrator' matches the LDAP configuration and update if there is a difference.
                if (!string.IsNullOrEmpty(AdminFilter) && !string.Equals(AdminFilter, "_disabled_", StringComparison.Ordinal))
                {
                    var isJellyfinAdmin = user.HasPermission(PermissionKind.IsAdministrator);
                    if (isJellyfinAdmin != ldapIsAdmin)
                    {
                        _logger.LogDebug("Updating user {Username} admin status to: {LdapIsAdmin}.", ldapUsername, ldapIsAdmin);
                        user.SetPermission(PermissionKind.IsAdministrator, ldapIsAdmin);
                        userNeedsUpdate = true;
                    }
                }

                if (userNeedsUpdate)
                {
                    await userManager.UpdateUserAsync(user).ConfigureAwait(false);
                }
            }

            return new ProviderAuthenticationResult { Username = ldapUsername };
        }

        /// <inheritdoc />
        public bool HasPassword(User user)
        {
            return true;
        }

        /// <summary>
        /// Changes the users password (Requires privileged bind user).
        /// </summary>
        /// <param name="user">The user who's password will be changed.</param>
        /// <param name="newPassword">The new password to set.</param>
        /// <returns>Completed Task notification.</returns>
        /// <exception cref="NotImplementedException">Thrown if AllowPassChange set to false.</exception>
        /// <exception cref="InvalidOperationException">Thrown if LdapPasswordAttribute field is null or empty.</exception>
        public Task ChangePassword(User user, string newPassword)
        {
            if (!LdapPlugin.Instance.Configuration.AllowPassChange)
            {
                throw new NotImplementedException();
            }

            if (string.IsNullOrEmpty(LdapPlugin.Instance.Configuration.LdapPasswordAttribute))
            {
                throw new InvalidOperationException("Password attribute is not set");
            }

            var passAttr = LdapPlugin.Instance.Configuration.LdapPasswordAttribute;
            var ldapUser = LocateLdapUser(user.Username);
            using var ldapClient = ConnectToLdap();
            var ldapAttr = new LdapAttribute(passAttr, newPassword);
            var ldapMod = new LdapModification(LdapModification.Replace, ldapAttr);
            ldapClient.Modify(ldapUser.Dn, ldapMod);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Deligate for validating LDAP server cert against a user provided CA.
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="certificate">TLS certificate provided by the server.</param>
        /// <param name="chain">TLS chain provided by the server.</param>
        /// <param name="sslPolicyErrors">Bitset of possible policy errors with the server's certificate.</param>
        /// <returns>True if server cert is valid and trusted by the CA, otherwise false.</returns>
        private bool LdapClient_UserDefinedServerCertValidationDelegate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)
                || sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
            {
                _logger.LogWarning("Provided certificate not valid for remote name");
                return false;
            }

            using var rootChain = new X509Chain
            {
                ChainPolicy =
                {
                    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
                                        | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                                        | X509VerificationFlags.IgnoreCtlNotTimeValid
                                        | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown
                                        | X509VerificationFlags.IgnoreEndRevocationUnknown,
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                }
            };
            rootChain.ChainPolicy.CustomTrustStore.ImportFromPemFile(LdapPlugin.Instance.Configuration.LdapRootCaPath);
            using var cert = new X509Certificate2(certificate);
            var result = rootChain.Build(cert);
            foreach (var error in chain.ChainStatus)
            {
                _logger.LogWarning("{State}: {Information}", error.Status.ToString(), error.StatusInformation);
            }

            return result;
        }

        /// <summary>
        /// Deligate for skipping TLS validation.
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="certificate">TLS certificate provided by the server.</param>
        /// <param name="chain">TLS chain provided by the server.</param>
        /// <param name="sslPolicyErrors">Bitset of possible policy errors with the server's certificate.</param>
        /// <returns>True.</returns>
        private static bool LdapClient_IgnoreCertDelegate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            System.Net.Security.SslPolicyErrors sslPolicyErrors)
            => true;

        /// <summary>
        /// Deligate for selecting which client cert to provide to the LDAP server for client auth.
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="host">Hostname you are connecting to.</param>
        /// <param name="localCerts">Local client certs.</param>
        /// <param name="remoteCert">Certificate provided by the remote party.</param>
        /// <param name="issuers">Valid certificate issuers for the remote party.</param>
        /// <returns>First client cert if available, otherwise remoteCert.</returns>
        private static X509Certificate LdapClient_CertificateSelectorDelegate(
            object sender,
            string host,
            X509CertificateCollection localCerts,
            X509Certificate remoteCert,
            string[] issuers)
        {
            if (localCerts.Count > 0)
            {
                return localCerts[0];
            }

            return remoteCert;
        }

        /// <summary>
        /// Returns the user search results for the provided filter.
        /// </summary>
        /// <param name="filter">The LDAP filter to search on.</param>
        /// <returns>The user DNs from the search results.</returns>
        /// <exception cref="AuthenticationException">Thrown on failure to connect or bind to LDAP server.</exception>
        /// <exception cref="LdapException">Thrown on failure to execute the search.</exception>
        public IEnumerable<string> GetFilteredUsers(string filter)
        {
            using var ldapClient = ConnectToLdap();

            ldapClient.Constraints = GetSearchConstraints(
                ldapClient,
                LdapPlugin.Instance.Configuration.LdapBindUser,
                LdapPlugin.Instance.Configuration.LdapBindPassword);

            try
            {
                var ldapUsers = ldapClient.Search(
                    LdapPlugin.Instance.Configuration.LdapBaseDn,
                    LdapConnection.ScopeSub,
                    filter,
                    new[] { UsernameAttr, UidAttr },
                    false);

                // ToList to ensure enumeration is complete before the connection is closed
                return ldapUsers.Select(u => u.Dn).ToList();
            }
            catch (LdapException e)
            {
                _logger.LogWarning(e, "Failed to filter users with: {Filter}", filter);
                throw;
            }
        }

        /// <summary>
        /// Attempts to locate the requested username on the ldap using the plugin-configured search and attribute settings.
        /// </summary>
        /// <param name="username">The username to search.</param>
        /// <returns>The located user or null if not found.</returns>
        /// <exception cref="AuthenticationException">Thrown on failure to connect or bind to LDAP server.</exception>
        public LdapEntry LocateLdapUser(string username)
        {
            using var ldapClient = ConnectToLdap();

            if (!ldapClient.Connected)
            {
                return null;
            }

            ldapClient.Constraints = GetSearchConstraints(
                ldapClient,
                LdapPlugin.Instance.Configuration.LdapBindUser,
                LdapPlugin.Instance.Configuration.LdapBindPassword);

            string sanitizedUsername = LdapUtils.SanitizeFilter(username);

            string realSearchFilter;

            if (SearchFilter.Contains("{username}", StringComparison.OrdinalIgnoreCase))
            {
                realSearchFilter = SearchFilter.Replace("{username}", sanitizedUsername, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                var searchFilterBuilder = new StringBuilder()
                    .Append("(&")
                    .Append(SearchFilter)
                    .Append("(|");

                foreach (var attr in LdapUsernameAttributes)
                {
                    searchFilterBuilder
                        .Append('(')
                        .Append(attr)
                        .Append('=')
                        .Append(sanitizedUsername)
                        .Append(')');
                }

                searchFilterBuilder.Append("))");
                realSearchFilter = searchFilterBuilder.ToString();
            }

            _logger.LogDebug(
                "LDAP Search: {BaseDn} {realSearchFilter} @ {LdapServer}",
                LdapPlugin.Instance.Configuration.LdapBaseDn,
                realSearchFilter,
                LdapPlugin.Instance.Configuration.LdapServer);

            ILdapSearchResults ldapUsers;
            try
            {
                ldapUsers = ldapClient.Search(
                    LdapPlugin.Instance.Configuration.LdapBaseDn,
                    LdapConnection.ScopeSub,
                    realSearchFilter,
                    new[] { UsernameAttr, UidAttr, ProfileImageAttr },
                    false);
            }
            catch (LdapException e)
            {
                _logger.LogError(e, "Failed to filter users with: {Filter}", realSearchFilter);
                throw new AuthenticationException("Error completing LDAP login while applying user filter.");
            }

            if (ldapUsers.HasMore())
            {
                LdapEntry ldapUser = ldapUsers.Next();

                if (ldapUsers.HasMore())
                {
                    _logger.LogWarning("More than one LDAP result matched; using first result only.");
                }

                _logger.LogDebug("LDAP User: {ldapUser}", ldapUser);

                return ldapUser;
            }
            else
            {
                _logger.LogError("Found no users matching {Username} in LDAP search", username);
                throw new AuthenticationException("Found no LDAP users matching provided username.");
            }
        }

        /// <inheritdoc />
        public Task<ForgotPasswordResult> StartForgotPasswordProcess(User user, bool isInNetwork)
        {
            var resetUrl = LdapPlugin.Instance.Configuration.PasswordResetUrl;
            if (string.IsNullOrEmpty(resetUrl))
            {
                throw new NotImplementedException();
            }

            resetUrl = resetUrl
                .Replace("$userId", user.Id.ToString(), StringComparison.OrdinalIgnoreCase)
                .Replace("$userName", user.Username, StringComparison.OrdinalIgnoreCase);

            var result = new ForgotPasswordResult
            {
                Action = ForgotPasswordAction.PinCode,
                PinFile = resetUrl
            };

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public Task<PinRedeemResult> RedeemPasswordResetPin(string pin)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Retrieves the requested attribute from a <see cref="LdapEntry" />.
        /// </summary>
        /// <param name="userEntry">The <see cref="LdapEntry" /> to retrieve the attribute from.</param>
        /// <param name="attr">The attribute to retrieve from the <see cref="LdapEntry" />.</param>
        /// <returns>The value of the <see cref="LdapEntry" /> or null if it does not exist.</returns>
        public LdapAttribute GetAttribute(LdapEntry userEntry, string attr)
        {
            var attributeSet = userEntry.GetAttributeSet();
            if (attributeSet.ContainsKey(attr))
            {
                return attributeSet.GetAttribute(attr);
            }

            _logger.LogWarning("LDAP attribute {Attr} not found for user {User}", attr, userEntry.Dn);
            return null;
        }

        private LdapConnectionOptions GetConnectionOptions()
        {
            var connectionOptions = new LdapConnectionOptions();
            var configuration = LdapPlugin.Instance.Configuration;
            if (configuration.UseSsl)
            {
                connectionOptions.UseSsl();
            }

            if (configuration.SkipSslVerify)
            {
                connectionOptions.ConfigureRemoteCertificateValidationCallback(LdapClient_IgnoreCertDelegate);
            }
            else if (!string.IsNullOrEmpty(configuration.LdapRootCaPath))
            {
                connectionOptions.ConfigureRemoteCertificateValidationCallback(LdapClient_UserDefinedServerCertValidationDelegate);
            }

            if (!string.IsNullOrEmpty(configuration.LdapClientCertPath) && !string.IsNullOrEmpty(configuration.LdapClientKeyPath))
            {
                var cert = X509Certificate2.CreateFromPemFile(configuration.LdapClientCertPath, configuration.LdapClientKeyPath);
                connectionOptions.ConfigureClientCertificates(new[] { cert });
                connectionOptions.ConfigureLocalCertificateSelectionCallback(LdapClient_CertificateSelectorDelegate);
            }

            return connectionOptions;
        }

        private LdapSearchConstraints GetSearchConstraints(
            LdapConnection ldapClient, string dn, string password)
        {
            var constraints = ldapClient.SearchConstraints;
            constraints.ReferralFollowing = true;
            constraints.setReferralHandler(new LdapAuthHandler(_logger, dn, password));
            return constraints;
        }

        private LdapConnection ConnectToLdap(string userDn = null, string userPassword = null)
        {
            bool initialConnection = userDn == null;
            if (initialConnection)
            {
                userDn = LdapPlugin.Instance.Configuration.LdapBindUser;
                userPassword = LdapPlugin.Instance.Configuration.LdapBindPassword;
            }

            // not using `using` for the ability to return ldapClient, need to dispose this manually on exception
            var ldapClient = new LdapConnection(GetConnectionOptions());
            try
            {
                ldapClient.Connect(LdapPlugin.Instance.Configuration.LdapServer, LdapPlugin.Instance.Configuration.LdapPort);
                if (LdapPlugin.Instance.Configuration.UseStartTls)
                {
                    ldapClient.StartTls();
                }

                _logger.LogDebug("Trying bind as user {UserDn}", userDn);
                ldapClient.Bind(userDn, userPassword);
            }
            catch (Exception e)
            {
                ldapClient.Dispose();

                _logger.LogError(e, "Failed to Connect or Bind to server as user {UserDn}", userDn);
                var message = initialConnection
                    ? "Failed to Connect or Bind to server."
                    : "Error completing LDAP login. Invalid username or password.";
                throw new AuthenticationException(message);
            }

            return ldapClient;
        }

        /// <summary>
        /// Tests the server connection and bind settings.
        /// </summary>
        /// <returns>A string reporting the result of the sequence of connection steps.</returns>
        public ServerTestResponse TestServerBind()
        {
            const string Started = "Testing...";
            const string Success = "Success";

            var configuration = LdapPlugin.Instance.Configuration;
            var connectionOptions = GetConnectionOptions();
            var response = new ServerTestResponse();

            try
            {
                response.Connect = Started;
                using var ldapClient = new LdapConnection(connectionOptions);
                ldapClient.Connect(configuration.LdapServer, configuration.LdapPort);
                response.Connect = Success;

                if (configuration.UseStartTls)
                {
                    response.StartTls = Started;
                    ldapClient.StartTls();
                    response.StartTls = Success;
                }

                response.Bind = Started;
                ldapClient.Bind(configuration.LdapBindUser, configuration.LdapBindPassword);
                response.Bind = ldapClient.Bound ? Success : "Anonymous";

                response.BaseSearch = Started;
                var entries = ldapClient.Search(
                    configuration.LdapBaseDn,
                    LdapConnection.ScopeSub,
                    string.Empty,
                    Array.Empty<string>(),
                    false);

                // entries.Count is unreliable (timing issue?), iterate to count
                var count = 0;
                while (entries.HasMore())
                {
                    entries.Next();
                    count++;
                }

                response.BaseSearch = $"Found {count} Entities";
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Ldap Test Failed to Connect or Bind to server");
                response.Error = e.Message;
            }

            return response;
        }
    }
}
