using System;
using System.Buffers.Text;
using System.Text;
using ICU4N.Impl;
using Jellyfin.Plugin.LDAP_Auth.Config;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;

namespace Jellyfin.Plugin.LDAP_Auth.Helpers;

/// <summary>
/// Provides utility methods for LDAP.
/// </summary>
public static class LdapUtils
{
    /// <summary>
    /// Sanitizes a string for use in LDAP search filters.
    /// <see href="https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md">OWASP LDAP Injection Prevention Cheat Sheet</see>.
    /// </summary>
    /// <param name="input">The input string to be sanitized.</param>
    /// <returns>The sanitized input string.</returns>
    public static string SanitizeFilter(string input)
    {
        StringBuilder sanitizedinput = new StringBuilder();

        foreach (char c in input)
        {
            switch (c)
            {
                case '\\':
                    sanitizedinput.Append("\\5c");
                    break;
                case '*':
                    sanitizedinput.Append("\\2a");
                    break;
                case '(':
                    sanitizedinput.Append("\\28");
                    break;
                case ')':
                    sanitizedinput.Append("\\29");
                    break;
                case '\u0000': // Null character
                    sanitizedinput.Append("\\00");
                    break;
                default:
                    sanitizedinput.Append(c);
                    break;
            }
        }

        return sanitizedinput.ToString();
    }

    internal static ProfileImageFormat TryDetermineAttributeFormat(LdapAttribute value, ILogger logger)
    {
        logger.LogDebug("Trying to determine ProfileImage Format based on Attribute value");
        var stringValue = value.StringValue;
        if (Uri.TryCreate(stringValue, UriKind.RelativeOrAbsolute, out var uri))
        {
            // URI must be absolute for it to contain the Scheme
            if (!uri.IsAbsoluteUri)
            {
                throw new InvalidFormatException($"ProfileImage Format detection failed. Expected absolute URI but attribute value appears to be a relative path. Got: {uri}");
            }

            // We can handle Url schemes as long as its http or https
            if (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            {
                logger.LogDebug("Attribute value was valid URI and scheme was one of (http, https). ImageFormat Url");
                return ProfileImageFormat.Url;
            }

            throw new InvalidFormatException($"ProfileImage Format detection failed. Attribute value was a valid URI but had an invalid Scheme, expected one of [http, https]. Got: {uri.Scheme}");
        }

        // If the string is entirely valid Base64 we are gonna assume it is Base64
        if (Base64.IsValid(stringValue))
        {
            logger.LogDebug("Attribute value was valid Base64. ImageFormat Base64");
            return ProfileImageFormat.Base64;
        }

        logger.LogDebug("Attribute value wasn't valid Uri or Base64. ImageFormat Binary");
        return ProfileImageFormat.Binary;
    }
}
