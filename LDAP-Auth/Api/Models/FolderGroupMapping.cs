namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Object representing a folder to group mapping.
    /// </summary>
    public class FolderGroupMapping
    {
        /// <summary>
        /// Gets or sets the folder.
        /// </summary>
        public string Folder { get; set; }

        /// <summary>
        /// Gets or sets the Groups allowed for given folder.
        /// </summary>
        public string[] Groups { get; set; }
    }
}
