using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.LDAP_Auth.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Model.Globalization;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;

namespace Jellyfin.Plugin.LDAP_Auth
{
    /// <summary>
    /// Ldap Authentication Provider Plugin.
    /// </summary>
    public class LdapProfileImageSyncTask : IScheduledTask
    {
        private readonly ILocalizationManager _localization;
        private readonly IApplicationHost _applicationHost;
        private readonly ILogger<LdapProfileImageSyncTask> _logger;
        private readonly IUserManager _userManager;
        private readonly IProviderManager _providerManager;
        private readonly IServerConfigurationManager _serverConfigurationManager;

        /// <summary>
        /// Initializes a new instance of the <see cref="LdapProfileImageSyncTask"/> class.
        /// </summary>
        /// <param name="applicationHost">Instance of the <see cref="IApplicationHost"/> interface.</param>
        /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
        /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface.</param>
        /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface.</param>
        /// <param name="logger">Instance of the <see cref="ILogger{LDAPImageSyncScheduledTask}"/> interface.</param>
        /// <param name="localization">Instance of the <see cref="ILocalizationManager"/> interface.</param>
        public LdapProfileImageSyncTask(
            IApplicationHost applicationHost,
            IUserManager userManager,
            IProviderManager providerManager,
            IServerConfigurationManager serverConfigurationManager,
            ILogger<LdapProfileImageSyncTask> logger,
            ILocalizationManager localization)
        {
            _logger = logger;
            _localization = localization;
            _applicationHost = applicationHost;
            _userManager = userManager;
            _providerManager = providerManager;
            _serverConfigurationManager = serverConfigurationManager;
        }

        private bool EnableProfileImageSync => LdapPlugin.Instance.Configuration.EnableLdapProfileImageSync;

        private string ProfileImageAttr => LdapPlugin.Instance.Configuration.LdapProfileImageAttribute;

        /// <inheritdoc/>
        public string Name => "LDAP - Synchronize profile images";

        /// <inheritdoc/>
        public string Key => "LdapProfileImageSync";

        /// <inheritdoc/>
        public string Description => "Synchronizes user profile images from LDAP.";

        /// <inheritdoc/>
        public string Category => _localization.GetLocalizedString("TasksApplicationCategory");

        /// <inheritdoc/>
        public async Task ExecuteAsync(IProgress<double> progress, CancellationToken cancellationToken)
        {
            if (!EnableProfileImageSync)
            {
                _logger.LogDebug("Synchronizing profile images is deactivated");
                return;
            }

            var ldapAuthProvider = _applicationHost.GetExports<LdapAuthenticationProviderPlugin>(false).First();
            var updatePluginConfig = false;

            foreach (var configUser in LdapPlugin.Instance.Configuration.GetAllLdapUsers())
            {
                var user = _userManager.GetUserById(configUser.LinkedJellyfinUserId);
                LdapEntry ldapUser;
                try
                {
                    ldapUser = ldapAuthProvider.LocateLdapUser(configUser.LdapUid);
                }
                catch (AuthenticationException)
                {
                    _logger.LogWarning("User '{configUser}' is not found in LDAP. Cannot synchronize profile image.", configUser.LdapUid);
                    continue;
                }

                var ldapProfileImage = ldapAuthProvider.GetAttribute(ldapUser, ProfileImageAttr)?.ByteValue;

                if (ldapProfileImage is not null)
                {
                    // Found a profile image in LDAP data. Check if image changed since last synchronization and update if so
                    var ldapProfileImageHash = Convert.ToBase64String(MD5.HashData(ldapProfileImage));

                    if (user.ProfileImage is null ||
                        !string.Equals(ldapProfileImageHash, configUser.ProfileImageHash, StringComparison.Ordinal))
                    {
                        _logger.LogDebug("Updating profile image for user {Username}", configUser.LdapUid);

                        if (user.ProfileImage is not null)
                        {
                            await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
                        }

                        await ProfileImageUpdater.SetProfileImage(user, ldapProfileImage, _serverConfigurationManager, _providerManager).ConfigureAwait(false);
                        configUser.ProfileImageHash = ldapProfileImageHash;
                        updatePluginConfig = true;

                        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                    }
                }
                else if (user.ProfileImage is not null)
                {
                    // Did not find a profile image in LDAP data but user still has a profile image set. Reset it.
                    _logger.LogDebug("Removing profile image for user {Username}", configUser.LdapUid);

                    try
                    {
                        File.Delete(user.ProfileImage.Path);
                    }
                    catch (IOException e)
                    {
                        _logger.LogError(e, "Error deleting user profile image during LDAP user profile image update");
                    }

                    configUser.ProfileImageHash = string.Empty;
                    updatePluginConfig = true;

                    await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
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
                    Type = TaskTriggerInfo.TriggerInterval,
                    IntervalTicks = TimeSpan.FromHours(24).Ticks
                }
            };
        }
    }
}
