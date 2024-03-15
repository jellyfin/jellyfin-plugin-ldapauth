using System.IO;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Data.Entities;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Providers;

namespace Jellyfin.Plugin.LDAP_Auth.Helpers
{
    /// <summary>
    /// Provides utility methods to update the profile image of a user.
    /// </summary>
    public static class ProfileImageUpdater
    {
        /// <summary>
        /// Sets the profile image of a user to the provided image.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <param name="ldapProfileImage">The data representing the profile image to set.</param>
        /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface, used to retrieve the path to save the profile picture.</param>
        /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface, used to save the profile picture.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public static async Task SetProfileImage(
            User user,
            byte[] ldapProfileImage,
            IServerConfigurationManager serverConfigurationManager,
            IProviderManager providerManager)
        {
            var userDataPath = Path.Combine(serverConfigurationManager.ApplicationPaths.UserConfigurationDirectoryPath, user.Username);
            user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile.jpg"));

            using var profileImageMemoryStream = new MemoryStream(ldapProfileImage);
            await providerManager
                .SaveImage(profileImageMemoryStream, MediaTypeNames.Image.Jpeg, user.ProfileImage.Path)
                .ConfigureAwait(false);
        }
    }
}
