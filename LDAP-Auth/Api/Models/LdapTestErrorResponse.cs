namespace Jellyfin.Plugin.LDAP_Auth.Api.Models
{
    /// <summary>
    /// Error response to pass message to client when LDAP testing fails.
    /// </summary>
    public class LdapTestErrorResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LdapTestErrorResponse"/> class.
        /// </summary>
        /// <param name="message">The error message.</param>
        public LdapTestErrorResponse(string message)
        {
            Message = message;
        }

        /// <summary>
        /// Gets the error message.
        /// </summary>
        public string Message { get; }
    }
}
