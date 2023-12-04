using System.Text;

namespace Jellyfin.Plugin.LDAP_Auth.Helpers
{
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
    }
}
