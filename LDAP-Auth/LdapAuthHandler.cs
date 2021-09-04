using System.Text;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;

namespace Jellyfin.Plugin.LDAP_Auth
{
    /// <summary>
    /// An authentication handler for automatically following LDAP referrals.
    /// </summary>
    /// <seealso href="https://www.novell.com/documentation/developer/ldapcsharp/?page=/documentation/developer/ldapcsharp/cnet/data/bp31k5d.html">
    /// Novell Referral Handling in LDAPv3: 4.4.3 Following Referrals Automatically with Authentication
    /// </seealso>
    internal sealed class LdapAuthHandler : ILdapAuthHandler
    {
        private readonly ILogger _logger;
        private readonly LdapAuthProvider _provider;

        /// <summary>
        /// Initializes a new instance of the <see cref="LdapAuthHandler" /> class.
        /// </summary>
        /// <param name="logger">Instance of the <see cref="ILogger"/> interface.</param>
        /// <param name="dn">The distinguised name to use when authenticating to the server.</param>
        /// <param name="password">The password to use when authenticating to the server.</param>
        public LdapAuthHandler(ILogger logger, string dn, string password)
        {
            _logger = logger;
            _provider = new LdapAuthProvider(dn, Encoding.UTF8.GetBytes(password));
        }

        /// <inheritdoc />
        public LdapAuthProvider GetAuthProvider(string host, int port)
        {
            _logger.LogDebug("Referred to {Host}:{Port}. Trying bind as user {Dn}", host, port, _provider.Dn);
            return _provider;
        }
    }
}
