namespace Jellyfin.Plugin.LDAP_Auth.Config;

/// <summary>
/// LDAP Profile Image attribute format.
/// </summary>
public enum ProfileImageFormat
{
    /// <summary>
    /// Default format. Tries to automatically determine what format the value is in.
    /// </summary>
    Default,

    /// <summary>
    /// Binary format with the raw bytes contained within the attribute.
    /// </summary>
    Binary,

    /// <summary>
    /// Base64 encoded string holding the binary data of the image.
    /// </summary>
    Base64,

    /// <summary>
    /// URL pointing to image.
    /// </summary>
    Url
}
