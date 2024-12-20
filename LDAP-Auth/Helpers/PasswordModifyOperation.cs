using System.IO;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Asn1;

namespace Jellyfin.Plugin.LDAP_Auth.Helpers
{
    /// <summary>
    /// RFC 3063: LDAP Password Modify Extended Operation
    /// https://tools.ietf.org/html/rfc3062.
    ///   <pre>
    ///     PasswdModifyRequestValue::= SEQUENCE {
    ///       userIdentity[0]  OCTET STRING OPTIONAL,
    ///       oldPasswd[1]     OCTET STRING OPTIONAL,
    ///       newPasswd[2]     OCTET STRING OPTIONAL }
    ///   </pre>
    /// </summary>
    public class PasswordModifyOperation : LdapExtendedOperation
    {
        /// <summary> Context-specific tag for optional userIdentity.</summary>
        private const int UserIdentityTag = 0;

        /// <summary> Context-specific tag for optional oldPasswd.</summary>
        private const int OldPasswdTag = 1;

        /// <summary> Context-specific tag for optional newPasswd.</summary>
        private const int NewPasswdTag = 2;

        /// <summary>
        /// According to RFC 4511 Section 5.1:
        /// The OCTET STRING type must always be encoded in the primitive (not constructed) form.
        /// </summary>
        private const bool ConstructedType = false;

        /// <summary>
        /// According to the complete ASN.1 definition in RFC 4511, Appendix B:
        /// Tags are always implicit (not explicit) unless otherwise stated.
        /// </summary>
        private const bool ExplicitTag = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordModifyOperation"/> class.
        /// </summary>
        /// <param name="userIdentity">
        /// A string that identifies the user whose password will be changed.
        /// This does not have to be a Distinguished Name but usually it is.
        /// Can be null or empty in which case the LDAP server is supposed to
        /// use the currently bound user.</param>
        /// <param name="oldPasswd">
        /// The user's current password. Used to authenticate the operation.
        /// Can be null or empty in which case the behavior is unspecified.
        /// Usually a null or empty oldPasswd will result in an error but some
        /// servers may allow it if certain conditions are met. For example,
        /// if the currently bound user is the RootDN user.
        /// </param>
        /// <param name="newPasswd">
        /// The desired new password. Can be null or empty in which case the
        /// LDAP server is supposed to generate a new password and send it
        /// with the response message (the 'genPasswd' field).  Some servers
        /// may not support or allow password generation and will send an
        /// error response instead.
        /// </param>
        public PasswordModifyOperation(string userIdentity, string oldPasswd, string newPasswd)
            : base(LdapKnownOids.Extensions.ModifyPassword, null)
        {
            var sequence = new Asn1Sequence(3);

            if (!string.IsNullOrEmpty(userIdentity))
            {
                var octetString = new Asn1OctetString(userIdentity);
                var id = new Asn1Identifier(Asn1Identifier.Context, ConstructedType, UserIdentityTag);

                sequence.Add(new Asn1Tagged(id, octetString, ExplicitTag));
            }

            if (!string.IsNullOrEmpty(oldPasswd))
            {
                var octetString = new Asn1OctetString(oldPasswd);
                var id = new Asn1Identifier(Asn1Identifier.Context, ConstructedType, OldPasswdTag);

                sequence.Add(new Asn1Tagged(id, octetString, ExplicitTag));
            }

            if (!string.IsNullOrEmpty(newPasswd))
            {
                var octetString = new Asn1OctetString(newPasswd);
                var id = new Asn1Identifier(Asn1Identifier.Context, ConstructedType, NewPasswdTag);

                sequence.Add(new Asn1Tagged(id, octetString, ExplicitTag));
            }

            var stream = new MemoryStream();
            sequence.Encode(new LberEncoder(), stream);

            SetValue(stream.ToArray());
        }
    }
}
