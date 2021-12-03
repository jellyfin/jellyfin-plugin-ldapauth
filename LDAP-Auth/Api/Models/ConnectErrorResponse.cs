namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Error response to pass message to client when LDAP connection fails.
    /// </summary>
    public class ConnectErrorResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConnectErrorResponse"/> class.
        /// </summary>
        /// <param name="message">The error message.</param>
        public ConnectErrorResponse(string message)
        {
            Message = message;
        }

        /// <summary>
        /// Gets the error message.
        /// </summary>
        public string Message { get; }
    }
}
