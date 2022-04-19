namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Response for testing server connection.
    /// </summary>
    public class ServerTestResponse
    {
        /// <summary>
        /// Gets or sets the connect result.
        /// </summary>
        public string Connect { get; set; }

        /// <summary>
        /// Gets or sets the Start TLS result.
        /// </summary>
        public string StartTls { get; set; }

        /// <summary>
        /// Gets or sets the bind result.
        /// </summary>
        public string Bind { get; set; }

        /// <summary>
        /// Gets or sets the Base DN search result.
        /// </summary>
        public string BaseSearch { get; set; }

        /// <summary>
        /// Gets or sets the error message.
        /// </summary>
        public string Error { get; set; }
    }
}
