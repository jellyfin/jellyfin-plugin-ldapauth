using System;
using System.Diagnostics;

using Jellyfin.Plugin.LDAP_Auth.Config;
using Novell.Directory.Ldap;

namespace Jellyfin.Plugin.LDAP_Auth.Helpers;

/// <summary>
/// Creates <see cref="LdapConnection"/> instances with connect and operation timeouts applied.
/// </summary>
/// <remarks>
/// Novell defaults leave <see cref="LdapConnection.ConnectionTimeout"/> at 0 (platform TCP timeout)
/// and <see cref="LdapConstraints.TimeLimit"/> at 0 (no API-enforced limit). Under host load that
/// can block auth threads for tens of seconds and leave the provider unable to complete later
/// logins until the process restarts (see jellyfin-plugin-ldapauth#187).
/// Prefer LDAPS (<c>UseSsl</c>) over StartTLS: Novell 3.6 <c>Dispose</c>/<c>Disconnect</c> after a
/// failed StartTLS session can block on SslStream teardown (dsbenghe/Novell.Directory.Ldap.NETStandard#101).
/// </remarks>
public static class LdapConnectionFactory
{
    /// <summary>
    /// Default TCP connect timeout in milliseconds when configuration is unset or invalid.
    /// </summary>
    public const int DefaultConnectTimeoutMs = 10_000;

    /// <summary>
    /// Default LDAP operation (bind/search) timeout in milliseconds when configuration is unset or invalid.
    /// </summary>
    public const int DefaultOperationTimeoutMs = 30_000;

    /// <summary>
    /// Creates a new <see cref="LdapConnection"/> with timeouts from <paramref name="configuration"/>.
    /// </summary>
    /// <param name="options">TLS and certificate options for the connection.</param>
    /// <param name="configuration">Plugin configuration supplying timeout values.</param>
    /// <returns>A new connection that has not yet been connected.</returns>
    public static LdapConnection Create(LdapConnectionOptions options, PluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(configuration);

        var ldapClient = new LdapConnection(options)
        {
            ConnectionTimeout = ResolveTimeout(configuration.LdapConnectTimeoutMs, DefaultConnectTimeoutMs)
        };

        ApplyOperationTimeout(ldapClient, configuration);
        return ldapClient;
    }

    /// <summary>
    /// Applies the configured operation <see cref="LdapConstraints.TimeLimit"/> to an existing connection.
    /// </summary>
    /// <param name="ldapClient">The connection to update.</param>
    /// <param name="configuration">Plugin configuration supplying timeout values.</param>
    public static void ApplyOperationTimeout(LdapConnection ldapClient, PluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(ldapClient);
        ArgumentNullException.ThrowIfNull(configuration);

        var constraints = ldapClient.Constraints;
        constraints.TimeLimit = ResolveTimeout(configuration.LdapOperationTimeoutMs, DefaultOperationTimeoutMs);
        ldapClient.Constraints = constraints;
    }

    /// <summary>
    /// Applies the configured operation timeout to search constraints (used when replacing constraints for referrals).
    /// </summary>
    /// <param name="constraints">Search constraints to update.</param>
    /// <param name="configuration">Plugin configuration supplying timeout values.</param>
    public static void ApplyOperationTimeout(LdapConstraints constraints, PluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        ArgumentNullException.ThrowIfNull(configuration);

        constraints.TimeLimit = ResolveTimeout(configuration.LdapOperationTimeoutMs, DefaultOperationTimeoutMs);
    }

    /// <summary>
    /// Resolves a configured timeout, substituting the default when the value is not positive.
    /// </summary>
    /// <param name="configuredMs">Configured milliseconds.</param>
    /// <param name="defaultMs">Fallback when <paramref name="configuredMs"/> is not positive.</param>
    /// <returns>A positive timeout in milliseconds.</returns>
    public static int ResolveTimeout(int configuredMs, int defaultMs)
    {
        return configuredMs > 0 ? configuredMs : defaultMs;
    }

    /// <summary>
    /// Starts a stopwatch for structured connect/bind timing logs.
    /// </summary>
    /// <returns>A started <see cref="Stopwatch"/>.</returns>
    public static Stopwatch StartTiming()
    {
        return Stopwatch.StartNew();
    }
}
