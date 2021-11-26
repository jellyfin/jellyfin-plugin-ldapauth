using System;
using System.Net.Mime;
using System.Text;
using Jellyfin.Plugin.LDAP_Auth.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;

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
        private readonly ILogger<LdapController> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="LdapController"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        public LdapController(ILogger<LdapController> logger)
        {
            _logger = logger;
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

            var connectionOptions = LdapAuthenticationProviderPlugin.GetConnectionOptions();

            var response = new StringBuilder();

            try
            {
                response.Append("Connect (");
                using var ldapClient = new LdapConnection(connectionOptions);
                ldapClient.Connect(configuration.LdapServer, configuration.LdapPort);
                response.Append("Success)");

                if (configuration.UseStartTls)
                {
                    response.Append("; Set StartTLS (");
                    ldapClient.StartTls();
                    response.Append("Success)");
                }

                response.Append("; Bind (");
                ldapClient.Bind(configuration.LdapBindUser, configuration.LdapBindPassword);
                response.Append("Success)");

                response.Append("; Base Search (");
                var entries = ldapClient.Search(
                    configuration.LdapBaseDn,
                    LdapConnection.ScopeSub,
                    string.Empty,
                    Array.Empty<string>(),
                    false);

                // entries.Count is unreliable (timing issue?), iterate to count
                var count = 0;
                while (entries.HasMore())
                {
                    entries.Next();
                    count++;
                }

                response.Append("Found ").Append(count).Append(" Entities)");
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Ldap Test Failed to Connect or Bind to server");
                response.Append("Error: ").Append(e.Message).Append(')');
            }

            return Ok(response.ToString());
        }
    }
}
