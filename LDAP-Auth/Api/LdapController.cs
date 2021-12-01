using System.Linq;
using System.Net.Mime;
using Jellyfin.Plugin.LDAP_Auth.Api.Models;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.LDAP_Auth.Api
{
    /// <summary>
    /// The LDAP api controller.
    /// </summary>
    [ApiController]
    [Authorize(Policy = "RequiresElevation")]
    [Route("[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    public class LdapController : ControllerBase
    {
        private readonly LdapAuthenticationProviderPlugin _ldapAuthenticationProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="LdapController"/> class.
        /// </summary>
        /// <param name="appHost">The application host to get the LDAP Authentication Provider from.</param>
        public LdapController(IApplicationHost appHost)
        {
            _ldapAuthenticationProvider = appHost.GetExports<IAuthenticationProvider>().OfType<LdapAuthenticationProviderPlugin>().FirstOrDefault();
        }

        /// <summary>
        /// Tests the server connection and bind settings.
        /// </summary>
        /// <remarks>
        /// Accepts server connection configuration as JSON body.
        /// </remarks>
        /// <response code="200">Server connection was tested.</response>
        /// <response code="400">Body is missing required data.</response>
        /// <param name="body">The request body.</param>
        /// <returns>
        /// A <see cref="OkResult"/> containing the connection results if able to test,
        /// or a <see cref="BadRequestResult"/> if the request body is missing data.
        /// </returns>
        [HttpPost("TestServerBind")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult TestServerBind([FromBody] ServerConnectionInfo body)
        {
            var configuration = LdapPlugin.Instance.Configuration;
            configuration.LdapServer = body.LdapServer;
            configuration.LdapPort = body.LdapPort;
            configuration.UseSsl = body.UseSsl;
            configuration.UseStartTls = body.UseStartTls;
            configuration.SkipSslVerify = body.SkipSslVerify;
            configuration.LdapBindUser = body.LdapBindUser;
            configuration.LdapBindPassword = body.LdapBindPassword;
            configuration.LdapBaseDn = body.LdapBaseDn;
            LdapPlugin.Instance.UpdateConfiguration(configuration);

            var result = _ldapAuthenticationProvider.TestServerBind();

            return Ok(new { Result = result });
        }
    }
}
