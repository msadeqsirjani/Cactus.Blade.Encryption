using Cactus.Blade.Encryption.Async;
using Cactus.Blade.Guard;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.XPath;
using Formatting = Newtonsoft.Json.Formatting;

namespace Cactus.Blade.Encryption.FieldLevel
{
    /// <summary>
    /// Defines extension methods for performing field-level encryption and decryption on XML and JSON documents.
    /// </summary>
    public static class FieldLevelEncryptionExtensions
    {
        /// <summary>
        /// Encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToEncrypt">The XPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields encrypted.</returns>
        public static string EncryptXml(this string xmlString, string xpathToEncrypt, string credentialName = null) =>
            Crypto.Current.EncryptXml(xmlString, xpathToEncrypt, credentialName);

        /// <summary>
        /// Encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathsToEncrypt">One or more XPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields encrypted.</returns>
        public static string EncryptXml(this string xmlString, IEnumerable<string> xpathsToEncrypt,
            string credentialName = null) =>
            Crypto.Current.EncryptXml(xmlString, xpathsToEncrypt, credentialName);

        /// <summary>
        /// Encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToEncrypt">The XPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields encrypted.</returns>
        public static string EncryptXml(this ICrypto crypto, string xmlString, string xpathToEncrypt,
            string credentialName = null) =>
            crypto.EncryptXml(xmlString, new[] { xpathToEncrypt }, credentialName);

        /// <summary>
        /// Encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToEncrypt">One or more XPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields encrypted.</returns>
        public static string EncryptXml(this ICrypto crypto, string xmlString, IEnumerable<string> xPathsToEncrypt,
            string credentialName = null)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(xmlString, nameof(xmlString));
            Guard.Guard.Against.Null(xPathsToEncrypt, nameof(xPathsToEncrypt));

            var document = new XmlDocument();
            document.LoadXml(xmlString);
            var navigator = document.CreateNavigator();

            var encryptor = new Lazy<IEncryptor>(() => crypto.GetEncryptor(credentialName));

            var anyPaths = false;

            foreach (var xpath in xPathsToEncrypt)
            {
                if (xpath.IsNull())
                    throw new ArgumentException($"{nameof(xPathsToEncrypt)} cannot have null items.",
                        nameof(xPathsToEncrypt));

                anyPaths = true;

                foreach (XPathNavigator match in navigator.Select(xpath))
                {
                    if (match.HasChildren && match.Value != match.InnerXml)
                    {
                        var plaintext = match.InnerXml;

                        while (match.MoveToFirstChild())
                            match.DeleteSelf();

                        match.SetValue(encryptor.Value.Encrypt(plaintext));
                    }
                    else
                    {
                        match.SetValue(encryptor.Value.Encrypt(match.Value));
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(xPathsToEncrypt)} must have at least one item.",
                    nameof(xPathsToEncrypt));

            return document.OuterXml;
        }

        /// <summary>
        /// Asynchronously encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToEncrypt">The XPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptXmlAsync(this string xmlString, string xpathToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.EncryptXmlAsync(xmlString, xpathToEncrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathsToEncrypt">One or more XPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptXmlAsync(this string xmlString, IEnumerable<string> xpathsToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.EncryptXmlAsync(xmlString, xpathsToEncrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToEncrypt">The XPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptXmlAsync(this ICrypto crypto, string xmlString, string xpathToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            crypto.EncryptXmlAsync(xmlString, new[] { xpathToEncrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToEncrypt">The XPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptXmlAsync(this IAsyncCrypto crypto, string xmlString, string xpathToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            crypto.EncryptXmlAsync(xmlString, new[] { xpathToEncrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToEncrypt">One or more XPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptXmlAsync(this ICrypto crypto, string xmlString,
            IEnumerable<string> xPathsToEncrypt, string credentialName = null,
            CancellationToken cancellationToken = default) =>
            crypto.AsAsync().EncryptXmlAsync(xmlString, xPathsToEncrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToEncrypt">One or more XPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields encrypted.</returns>
        public static async Task<string> EncryptXmlAsync(this IAsyncCrypto crypto, string xmlString,
            IEnumerable<string> xPathsToEncrypt, string credentialName = null,
            CancellationToken cancellationToken = default)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(xmlString, nameof(xmlString));
            Guard.Guard.Against.Null(xPathsToEncrypt, nameof(xPathsToEncrypt));

            var document = new XmlDocument();
            document.LoadXml(xmlString);
            var navigator = document.CreateNavigator();

            var encryptor = new Lazy<IAsyncEncryptor>(() => crypto.GetAsyncEncryptor(credentialName));

            var anyPaths = false;

            foreach (var xpath in xPathsToEncrypt)
            {
                if (xpath.IsNull())
                    throw new ArgumentException($"{nameof(xPathsToEncrypt)} cannot have null items.",
                        nameof(xPathsToEncrypt));

                anyPaths = true;

                foreach (XPathNavigator match in navigator.Select(xpath))
                {
                    if (match.HasChildren && match.Value != match.InnerXml)
                    {
                        var plaintext = match.InnerXml;

                        while (match.MoveToFirstChild())
                            match.DeleteSelf();

                        match.SetValue(await encryptor.Value.EncryptAsync(plaintext, cancellationToken)
                            .ConfigureAwait(false));
                    }
                    else
                    {
                        match.SetValue(await encryptor.Value.EncryptAsync(match.Value, cancellationToken)
                            .ConfigureAwait(false));
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(xPathsToEncrypt)} must have at least one item.",
                    nameof(xPathsToEncrypt));

            return document.OuterXml;
        }

        /// <summary>
        /// Decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToDecrypt">The XPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields decrypted.</returns>
        public static string DecryptXml(this string xmlString, string xpathToDecrypt, string credentialName = null) =>
            Crypto.Current.DecryptXml(xmlString, xpathToDecrypt, credentialName);

        /// <summary>
        /// Decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToDecrypt">One or more XPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields decrypted.</returns>
        public static string DecryptXml(this string xmlString, IEnumerable<string> xPathsToDecrypt,
            string credentialName = null) =>
            Crypto.Current.DecryptXml(xmlString, xPathsToDecrypt, credentialName);

        /// <summary>
        /// Decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToDecrypt">The XPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields decrypted.</returns>
        public static string DecryptXml(this ICrypto crypto, string xmlString, string xpathToDecrypt,
            string credentialName = null) =>
            crypto.DecryptXml(xmlString, new[] { xpathToDecrypt }, credentialName);

        /// <summary>
        /// Decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToDecrypt">One or more XPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same xml document, except with the specified fields decrypted.</returns>
        public static string DecryptXml(this ICrypto crypto, string xmlString, IEnumerable<string> xPathsToDecrypt,
            string credentialName = null)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(xmlString, nameof(xmlString));
            Guard.Guard.Against.Null(xPathsToDecrypt, nameof(xPathsToDecrypt));

            var doc = new XmlDocument();
            doc.LoadXml(xmlString);
            var navigator = doc.CreateNavigator();

            var decryptor = new Lazy<IDecryptor>(() => crypto.GetDecryptor(credentialName));

            var anyPaths = false;

            foreach (var xpath in xPathsToDecrypt)
            {
                if (xpath.IsNull())
                    throw new ArgumentException($"{nameof(xPathsToDecrypt)} cannot have null items.",
                        nameof(xPathsToDecrypt));

                anyPaths = true;

                foreach (XPathNavigator match in navigator.Select(xpath))
                {
                    var decrypted = decryptor.Value.Decrypt(match.InnerXml);
                    if (decrypted == match.InnerXml) continue;

                    try
                    {
                        match.InnerXml = decrypted;
                    }
                    catch
                    {
                        match.SetValue(decrypted);
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(xPathsToDecrypt)} must have at least one item.",
                    nameof(xPathsToDecrypt));

            return doc.OuterXml;
        }

        /// <summary>
        /// Asynchronously decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToDecrypt">The XPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptXmlAsync(this string xmlString, string xpathToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.DecryptXmlAsync(xmlString, xpathToDecrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToDecrypt">One or more XPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptXmlAsync(this string xmlString, IEnumerable<string> xPathsToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.DecryptXmlAsync(xmlString, xPathsToDecrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToDecrypt">The XPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptXmlAsync(this ICrypto crypto, string xmlString, string xpathToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            crypto.DecryptXmlAsync(xmlString, new[] { xpathToDecrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xpathToDecrypt">The XPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptXmlAsync(this IAsyncCrypto crypto, string xmlString, string xpathToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            crypto.DecryptXmlAsync(xmlString, new[] { xpathToDecrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToDecrypt">One or more XPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptXmlAsync(this ICrypto crypto, string xmlString,
            IEnumerable<string> xPathsToDecrypt, string credentialName = null,
            CancellationToken cancellationToken = default) =>
            crypto.AsAsync().DecryptXmlAsync(xmlString, xPathsToDecrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by XPath, that are contained in the given xml document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="xmlString">A string containing an xml document.</param>
        /// <param name="xPathsToDecrypt">One or more XPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same xml document, except with the specified fields decrypted.</returns>
        public static async Task<string> DecryptXmlAsync(this IAsyncCrypto crypto, string xmlString,
            IEnumerable<string> xPathsToDecrypt, string credentialName = null,
            CancellationToken cancellationToken = default)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(xmlString, nameof(xmlString));
            Guard.Guard.Against.Null(xPathsToDecrypt, nameof(xPathsToDecrypt));

            var document = new XmlDocument();
            document.LoadXml(xmlString);
            var navigator = document.CreateNavigator();

            var decryptor = new Lazy<IAsyncDecryptor>(() => crypto.GetAsyncDecryptor(credentialName));

            var anyPaths = false;

            foreach (var xpath in xPathsToDecrypt)
            {
                if (xpath.IsNull())
                    throw new ArgumentException($"{nameof(xPathsToDecrypt)} cannot have null items.",
                        nameof(xPathsToDecrypt));

                anyPaths = true;

                foreach (XPathNavigator match in navigator.Select(xpath))
                {
                    var decrypted = await decryptor.Value.DecryptAsync(match.InnerXml, cancellationToken)
                        .ConfigureAwait(false);
                    if (decrypted == match.InnerXml) continue;
                    try
                    {
                        match.InnerXml = decrypted;
                    }
                    catch
                    {
                        match.SetValue(decrypted);
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(xPathsToDecrypt)} must have at least one item.",
                    nameof(xPathsToDecrypt));

            return document.OuterXml;
        }

        /// <summary>
        /// Encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToEncrypt">The JSONPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields encrypted.</returns>
        public static string EncryptJson(this string jsonString, string jsonPathToEncrypt,
            string credentialName = null) =>
            Crypto.Current.EncryptJson(jsonString, jsonPathToEncrypt, credentialName);

        /// <summary>
        /// Encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToEncrypt">One or more JSONPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields encrypted.</returns>
        public static string EncryptJson(this string jsonString, IEnumerable<string> jsonPathsToEncrypt,
            string credentialName = null) =>
            Crypto.Current.EncryptJson(jsonString, jsonPathsToEncrypt, credentialName);

        /// <summary>
        /// Encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToEncrypt">The JSONPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields encrypted.</returns>
        public static string EncryptJson(this ICrypto crypto, string jsonString, string jsonPathToEncrypt,
            string credentialName = null) =>
            crypto.EncryptJson(jsonString, new[] { jsonPathToEncrypt }, credentialName);

        /// <summary>
        /// Encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToEncrypt">One or more JSONPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields encrypted.</returns>
        public static string EncryptJson(this ICrypto crypto, string jsonString, IEnumerable<string> jsonPathsToEncrypt,
            string credentialName = null)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(jsonString, nameof(jsonString));
            Guard.Guard.Against.Null(jsonPathsToEncrypt, nameof(jsonPathsToEncrypt));

            var token = JToken.Parse(jsonString);

            var encryptor = new Lazy<IEncryptor>(() => crypto.GetEncryptor(credentialName));

            var anyPaths = false;

            foreach (var jsonPath in jsonPathsToEncrypt)
            {
                if (jsonPath.IsNull())
                    throw new ArgumentException($"{nameof(jsonPathsToEncrypt)} cannot have null items.",
                        nameof(jsonPathsToEncrypt));

                anyPaths = true;

                foreach (var match in token.SelectTokens(jsonPath).ToArray())
                {
                    var encryptedToken =
                        JToken.Parse("\"" + encryptor.Value.Encrypt(match.ToString(Formatting.None)) + "\"");

                    if (token.ReferenceEquals(match))
                        return encryptedToken.ToString(Formatting.None);

                    switch (match.Parent)
                    {
                        case JProperty property:
                            property.Value = encryptedToken;
                            break;
                        case JArray array:
                            array[array.IndexOf(match)] = encryptedToken;
                            break;
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(jsonPathsToEncrypt)} must have at least one item.",
                    nameof(jsonPathsToEncrypt));

            return token.ToString(Formatting.None);
        }

        /// <summary>
        /// Asynchronously encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToEncrypt">The JSONPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptJsonAsync(this string jsonString, string jsonPathToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.EncryptJsonAsync(jsonString, jsonPathToEncrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToEncrypt">One or more JSONPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptJsonAsync(this string jsonString, IEnumerable<string> jsonPathsToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.EncryptJsonAsync(jsonString, jsonPathsToEncrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToEncrypt">The JSONPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptJsonAsync(this ICrypto crypto, string jsonString, string jsonPathToEncrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            crypto.EncryptJsonAsync(jsonString, new[] { jsonPathToEncrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToEncrypt">The JSONPath of the field to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptJsonAsync(this IAsyncCrypto crypto, string jsonString,
            string jsonPathToEncrypt, string credentialName = null,
            CancellationToken cancellationToken = default) =>
            crypto.EncryptJsonAsync(jsonString, new[] { jsonPathToEncrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToEncrypt">One or more JSONPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields encrypted.</returns>
        public static Task<string> EncryptJsonAsync(this ICrypto crypto, string jsonString,
            IEnumerable<string> jsonPathsToEncrypt, string credentialName = null,
            CancellationToken cancellationToken = default) =>
            crypto.AsAsync().EncryptJsonAsync(jsonString, jsonPathsToEncrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously encrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing encryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToEncrypt">One or more JSONPaths of the fields to encrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields encrypted.</returns>
        public static async Task<string> EncryptJsonAsync(this IAsyncCrypto crypto, string jsonString,
            IEnumerable<string> jsonPathsToEncrypt, string credentialName = null,
            CancellationToken cancellationToken = default)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(jsonString, nameof(jsonString));
            Guard.Guard.Against.Null(jsonPathsToEncrypt, nameof(jsonPathsToEncrypt));

            var token = JToken.Parse(jsonString);

            var encryptor = new Lazy<IAsyncEncryptor>(() => crypto.GetAsyncEncryptor(credentialName));

            var anyPaths = false;

            foreach (var jsonPath in jsonPathsToEncrypt)
            {
                if (jsonPath.IsNull())
                    throw new ArgumentException($"{nameof(jsonPathsToEncrypt)} cannot have null items.",
                        nameof(jsonPathsToEncrypt));

                anyPaths = true;

                foreach (var match in token.SelectTokens(jsonPath).ToArray())
                {
                    var encryptedToken = JToken.Parse("\"" +
                                                      await encryptor.Value.EncryptAsync(
                                                          match.ToString(Formatting.None), cancellationToken) + "\"");

                    if (token.ReferenceEquals(match))
                        return encryptedToken.ToString(Formatting.None);

                    switch (match.Parent)
                    {
                        case JProperty property:
                            property.Value = encryptedToken;
                            break;
                        case JArray array:
                            array[array.IndexOf(match)] = encryptedToken;
                            break;
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(jsonPathsToEncrypt)} must have at least one item.",
                    nameof(jsonPathsToEncrypt));

            return token.ToString(Formatting.None);
        }

        /// <summary>
        /// Decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToDecrypt">The JSONPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields decrypted.</returns>
        public static string DecryptJson(this string jsonString, string jsonPathToDecrypt,
            string credentialName = null) =>
            Crypto.Current.DecryptJson(jsonString, jsonPathToDecrypt, credentialName);

        /// <summary>
        /// Decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToDecrypt">One or more JSONPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields decrypted.</returns>
        public static string DecryptJson(this string jsonString, IEnumerable<string> jsonPathsToDecrypt,
            string credentialName = null) =>
            Crypto.Current.DecryptJson(jsonString, jsonPathsToDecrypt, credentialName);

        /// <summary>
        /// Decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToDecrypt">The JSONPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields decrypted.</returns>
        public static string DecryptJson(this ICrypto crypto, string jsonString, string jsonPathToDecrypt,
            string credentialName = null) =>
            crypto.DecryptJson(jsonString, new[] { jsonPathToDecrypt }, credentialName);

        /// <summary>
        /// Decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToDecrypt">One or more JSONPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <returns>The same json document, except with the specified fields decrypted.</returns>
        public static string DecryptJson(this ICrypto crypto, string jsonString, IEnumerable<string> jsonPathsToDecrypt,
            string credentialName = null)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(jsonString, nameof(jsonString));
            Guard.Guard.Against.Null(jsonPathsToDecrypt, nameof(jsonPathsToDecrypt));

            var token = JToken.Parse(jsonString);

            var decryptor = new Lazy<IDecryptor>(() => crypto.GetDecryptor(credentialName));

            var anyPaths = false;

            foreach (var jsonPath in jsonPathsToDecrypt)
            {
                if (jsonPath.IsNull())
                    throw new ArgumentException($"{nameof(jsonPathsToDecrypt)} cannot have null items.",
                        nameof(jsonPathsToDecrypt));

                anyPaths = true;

                foreach (var match in token.SelectTokens(jsonPath).ToArray())
                {
                    var decryptedToken = JToken.Parse(decryptor.Value.Decrypt(match.Value<string>()));

                    if (token.ReferenceEquals(match))
                    {
                        token = decryptedToken;
                        continue;
                    }

                    switch (match.Parent)
                    {
                        case JProperty property:
                            property.Value = decryptedToken;
                            break;
                        case JArray array:
                            array[array.IndexOf(match)] = decryptedToken;
                            break;
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(jsonPathsToDecrypt)} must have at least one item.",
                    nameof(jsonPathsToDecrypt));

            return token.ToString(Formatting.None);
        }

        /// <summary>
        /// Asynchronously decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToDecrypt">The JSONPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptJsonAsync(this string jsonString, string jsonPathToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.DecryptJsonAsync(jsonString, jsonPathToDecrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToDecrypt">One or more JSONPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptJsonAsync(this string jsonString, IEnumerable<string> jsonPathsToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            Crypto.Current.DecryptJsonAsync(jsonString, jsonPathsToDecrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToDecrypt">The JSONPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptJsonAsync(this ICrypto crypto, string jsonString, string jsonPathToDecrypt,
            string credentialName = null, CancellationToken cancellationToken = default) =>
            crypto.DecryptJsonAsync(jsonString, new[] { jsonPathToDecrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathToDecrypt">The JSONPath of the field to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptJsonAsync(this IAsyncCrypto crypto, string jsonString,
            string jsonPathToDecrypt, string credentialName = null,
            CancellationToken cancellationToken = default) =>
            crypto.DecryptJsonAsync(jsonString, new[] { jsonPathToDecrypt }, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="ICrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToDecrypt">One or more JSONPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields decrypted.</returns>
        public static Task<string> DecryptJsonAsync(this ICrypto crypto, string jsonString,
            IEnumerable<string> jsonPathsToDecrypt, string credentialName = null,
            CancellationToken cancellationToken = default) =>
            crypto.AsAsync().DecryptJsonAsync(jsonString, jsonPathsToDecrypt, credentialName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts the fields, specified by JSONPath, that are contained in the given json document string.
        /// </summary>
        /// <param name="crypto">
        /// The instance of <see cref="IAsyncCrypto"/> that ultimately responsible for performing decryption operations
        /// on field values.
        /// </param>
        /// <param name="jsonString">A string containing an json document.</param>
        /// <param name="jsonPathsToDecrypt">One or more JSONPaths of the fields to decrypt.</param>
        /// <param name="credentialName">
        /// The name of the credential to use for this encryption operation,
        /// or null to use the default credential.
        /// </param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
        /// <returns>A task that will contain the same json document, except with the specified fields decrypted.</returns>
        public static async Task<string> DecryptJsonAsync(this IAsyncCrypto crypto, string jsonString,
            IEnumerable<string> jsonPathsToDecrypt, string credentialName = null,
            CancellationToken cancellationToken = default)
        {
            Guard.Guard.Against.Null(crypto, nameof(crypto));
            Guard.Guard.Against.Null(jsonString, nameof(jsonString));
            Guard.Guard.Against.Null(jsonPathsToDecrypt, nameof(jsonPathsToDecrypt));

            var token = JToken.Parse(jsonString);

            var decryptor = new Lazy<IAsyncDecryptor>(() => crypto.GetAsyncDecryptor(credentialName));

            var anyPaths = false;

            foreach (var jsonPath in jsonPathsToDecrypt)
            {
                if (jsonPath.IsNull())
                    throw new ArgumentException($"{nameof(jsonPathsToDecrypt)} cannot have null items.",
                        nameof(jsonPathsToDecrypt));

                anyPaths = true;

                foreach (var match in token.SelectTokens(jsonPath).ToArray())
                {
                    var decryptedToken =
                        JToken.Parse(await decryptor.Value.DecryptAsync(match.Value<string>(), cancellationToken));

                    if (token.ReferenceEquals(match))
                    {
                        token = decryptedToken;
                        continue;
                    }

                    switch (match.Parent)
                    {
                        case JProperty property:
                            property.Value = decryptedToken;
                            break;
                        case JArray array:
                            array[array.IndexOf(match)] = decryptedToken;
                            break;
                    }
                }
            }

            if (!anyPaths)
                throw new ArgumentException($"{nameof(jsonPathsToDecrypt)} must have at least one item.",
                    nameof(jsonPathsToDecrypt));

            return token.ToString(Formatting.None);
        }
    }
}
