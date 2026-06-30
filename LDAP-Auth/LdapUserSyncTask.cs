using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.LDAP_Auth.Api.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Globalization;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;

namespace Jellyfin.Plugin.LDAP_Auth
{
    /// <summary>
    /// Scheduled task that creates Jellyfin users for LDAP users matching the search filter.
    /// </summary>
    public class LdapUserSyncTask : IScheduledTask
    {
        private readonly ILocalizationManager _localization;
        private readonly IApplicationHost _applicationHost;
        private readonly ILogger<LdapUserSyncTask> _logger;
        private readonly IUserManager _userManager;

        /// <summary>
        /// Initializes a new instance of the <see cref="LdapUserSyncTask"/> class.
        /// </summary>
        /// <param name="applicationHost">Instance of the <see cref="IApplicationHost"/> interface.</param>
        /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
        /// <param name="logger">Instance of the <see cref="ILogger{LdapUserSyncTask}"/> interface.</param>
        /// <param name="localization">Instance of the <see cref="ILocalizationManager"/> interface.</param>
        public LdapUserSyncTask(
            IApplicationHost applicationHost,
            IUserManager userManager,
            ILogger<LdapUserSyncTask> logger,
            ILocalizationManager localization)
        {
            _applicationHost = applicationHost;
            _userManager = userManager;
            _logger = logger;
            _localization = localization;
        }

        private string UidAttr => LdapPlugin.Instance.Configuration.LdapUidAttribute;

        private string UsernameAttr => LdapPlugin.Instance.Configuration.LdapUsernameAttribute;

        /// <inheritdoc/>
        public string Name => "LDAP - Synchronize users";

        /// <inheritdoc/>
        public string Key => "LdapUserSync";

        /// <inheritdoc/>
        public string Description => "Creates Jellyfin users for LDAP users matching the search filter.";

        /// <inheritdoc/>
        public string Category => _localization.GetLocalizedString("TasksApplicationCategory");

        /// <inheritdoc/>
        public async Task ExecuteAsync(IProgress<double> progress, CancellationToken cancellationToken)
        {
            if (!LdapPlugin.Instance.Configuration.CreateUsersFromLdap)
            {
                _logger.LogDebug("Creating users from LDAP is deactivated, skipping user sync");
                return;
            }

            var ldapAuthProvider = _applicationHost.GetExports<LdapAuthenticationProviderPlugin>(false).First();
            var providerName = typeof(LdapAuthenticationProviderPlugin).FullName!;
            var updatePluginConfig = false;

            foreach (var ldapUser in ldapAuthProvider.GetLdapUsers())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var ldapUid = ldapAuthProvider.GetAttribute(ldapUser, UidAttr)?.StringValue;
                var ldapUsername = ldapAuthProvider.GetAttribute(ldapUser, UsernameAttr)?.StringValue;
                if (string.IsNullOrEmpty(ldapUid) || string.IsNullOrEmpty(ldapUsername))
                {
                    _logger.LogWarning("Skipping LDAP user {Dn} with missing uid or username attribute", ldapUser.Dn);
                    continue;
                }

                var ldapIsAdmin = ldapAuthProvider.IsLdapUserAdmin(ldapUser, ldapUsername);

                // Resolve the linked Jellyfin user, if any.
                User user = null;
                if (UserHelper.GetLdapUser(ldapUid) is { } configUser)
                {
                    user = _userManager.GetUserById(configUser.LinkedJellyfinUserId);
                }

                // Not yet linked: link an existing same-named user if it is managed by us.
                if (user is null)
                {
                    var existingUser = _userManager.GetUserByName(ldapUsername);
                    if (existingUser is not null)
                    {
                        if (!string.Equals(existingUser.AuthenticationProviderId, providerName, StringComparison.OrdinalIgnoreCase))
                        {
                            // A user with this name exists but is not managed by us; leave it alone.
                            continue;
                        }

                        user = existingUser;
                        LdapPlugin.Instance.Configuration.AddUser(user.Id, ldapUid, string.Empty);
                        updatePluginConfig = true;
                    }
                }

                if (user is null)
                {
                    _logger.LogInformation("Creating Jellyfin user {Username} from LDAP - is admin? {IsAdmin}", ldapUsername, ldapIsAdmin);
                    user = await _userManager.CreateUserAsync(ldapUsername).ConfigureAwait(false);
                    user.AuthenticationProviderId = providerName;
                    user.PasswordResetProviderId = providerName;
                    user.SetPermission(PermissionKind.IsAdministrator, ldapIsAdmin);
                    user.SetPermission(PermissionKind.EnableAllFolders, LdapPlugin.Instance.Configuration.EnableAllFolders);
                    if (!LdapPlugin.Instance.Configuration.EnableAllFolders)
                    {
                        user.SetPreference(PreferenceKind.EnabledFolders, LdapPlugin.Instance.Configuration.EnabledFolders);
                    }

                    await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

                    LdapPlugin.Instance.Configuration.AddUser(user.Id, ldapUid, string.Empty);
                    updatePluginConfig = true;
                    continue;
                }

                // Existing user: keep its admin status in sync, but only when an admin
                // filter is configured so we never demote users the filter cannot evaluate.
                if (ldapAuthProvider.IsAdminFilterEnabled
                    && user.HasPermission(PermissionKind.IsAdministrator) != ldapIsAdmin)
                {
                    _logger.LogInformation("Updating user {Username} admin status to: {IsAdmin}", ldapUsername, ldapIsAdmin);
                    user.SetPermission(PermissionKind.IsAdministrator, ldapIsAdmin);
                    await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                }
            }

            if (updatePluginConfig)
            {
                LdapPlugin.Instance.SaveConfiguration();
            }
        }

        /// <inheritdoc/>
        public IEnumerable<TaskTriggerInfo> GetDefaultTriggers()
        {
            return new[]
            {
                new TaskTriggerInfo
                {
                    Type = TaskTriggerInfoType.IntervalTrigger,
                    IntervalTicks = TimeSpan.FromHours(24).Ticks
                }
            };
        }
    }
}
