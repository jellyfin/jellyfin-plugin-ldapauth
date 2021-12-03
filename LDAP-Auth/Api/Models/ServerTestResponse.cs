namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Response for testing server connection.
    /// </summary>
    public class ServerTestResponse
    {
        /// <summary>
        /// Gets or sets the server connection result message.
        /// </summary>
        public string Result { get; set; }
    }
}
