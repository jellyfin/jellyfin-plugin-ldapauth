using System;
using System.Collections.Generic;
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
        /// An <see cref="OkResult"/> containing the connection results if able to test,
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

        /// <summary>
        /// Tests the LDAP user and admin filters.
        /// </summary>
        /// <remarks>
        /// Accepts server connection configuration as JSON body.
        /// </remarks>
        /// <response code="200">Filters were queried.</response>
        /// <response code="400">Body is missing required data.</response>
        /// <response code="401">Failed to connect to LDAP server.</response>
        /// <param name="body">The request body.</param>
        /// <returns>
        /// An <see cref="OkResult"/> containing the connection results if able to test,
        /// an <see cref="UnauthorizedResult"/> if unable to connect to the LDAP server,
        /// or a <see cref="BadRequestResult"/> if the request body is missing data.
        /// </returns>
        [HttpPost("TestLdapFilters")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult TestLdapFilters([FromBody] UserFilterInfo body)
        {
            var configuration = LdapPlugin.Instance.Configuration;
            configuration.LdapSearchFilter = body.LdapSearchFilter;
            configuration.LdapAdminFilter = body.LdapAdminFilter;
            LdapPlugin.Instance.UpdateConfiguration(configuration);

            try
            {
                var users = _ldapAuthenticationProvider.GetFilteredUsers(configuration.LdapSearchFilter).ToHashSet();

                HashSet<string> admins = new HashSet<string>();
                if (!string.IsNullOrEmpty(configuration.LdapAdminFilter) && !string.Equals(configuration.LdapAdminFilter, "_disabled_", StringComparison.Ordinal))
                {
                    admins = _ldapAuthenticationProvider.GetFilteredUsers(configuration.LdapAdminFilter).ToHashSet();
                }

                var isSubset = admins.IsSubsetOf(users);

                return Ok(new { Users = users.Count, Admins = admins.Count, IsSubset = isSubset });
            }
            catch (AuthenticationException e)
            {
                return Unauthorized(new { Message = e.Message });
            }
        }

        /// <summary>
        /// Saves the LDAP search attributes and optionally tests a query string.
        /// </summary>
        /// <remarks>
        /// Accepts search attributes and test query as JSON body.
        /// </remarks>
        /// <response code="200">No test requested or test completed.</response>
        /// <response code="400">Body is missing required data.</response>
        /// <response code="401">Failed to connect to LDAP server.</response>
        /// <param name="body">The request body.</param>
        /// <returns>
        /// An <see cref="OkResult"/> containing the test results,
        /// an <see cref="UnauthorizedResult"/> if unable to connect to the LDAP server,
        /// or a <see cref="BadRequestResult"/> if the request body is missing data.
        /// </returns>
        [HttpPost("LdapUserSearch")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult LdapUserSearch([FromBody] UserSearchAttributes body)
        {
            var configuration = LdapPlugin.Instance.Configuration;
            configuration.LdapSearchAttributes = body.LdapSearchAttributes;
            configuration.EnableCaseInsensitiveUsername = body.EnableCaseInsensitiveUsername;
            LdapPlugin.Instance.UpdateConfiguration(configuration);

            if (string.IsNullOrEmpty(body.TestSearchUsername))
            {
                return Ok(new { });
            }

            try
            {
                var user = _ldapAuthenticationProvider.LocateLdapUser(body.TestSearchUsername);
                return Ok(new { Found = user?.Dn });
            }
            catch (AuthenticationException e)
            {
                return Unauthorized(new { Message = e.Message });
            }
        }
    }
}
