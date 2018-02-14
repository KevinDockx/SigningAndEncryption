using Jose;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Marvin.SigningAndEncryption.Controllers
{
    [Route("api/signencrypt")]
    public class SignEncryptController : Controller
    {
        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            var payloadToSign = new Dictionary<string, object>()
            {
                { "sub", "signedkevin" },
                { "exp", 1300819380 }
            };

            // TEST signing

            // sign with private key, check signature with public key (you can also check the signature
            // with the private key of course, but that one shouldn't be given away ;))
            var signingCertificate = new X509Certificate2(@"Certificates\test-sign.pfx", "Test",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            var privateSigningKey = signingCertificate.PrivateKey as RSACryptoServiceProvider;
            var signedToken = Jose.JWT.Encode(payloadToSign, privateSigningKey, JwsAlgorithm.RS256);

            var publicSigningKey = signingCertificate.PublicKey.Key as RSACryptoServiceProvider;
            var decodedToken = Jose.JWT.Decode(signedToken, publicSigningKey);

            // TEST encryption
            // encrypt with the public key, decrypt with the private key

            var payloadToEncrypt = new Dictionary<string, object>()
            {
                { "sub", "encryptedkevin" },
                { "exp", 1300819380 }
            };

            var encryptionCertificate = new X509Certificate2(@"Certificates\test-encrypt.pfx", "Test",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            // encrypt with public key
            var publicEncryptionKey = encryptionCertificate.PublicKey.Key as RSACryptoServiceProvider;
            var encryptedPayload = Jose.JWT.Encode(payloadToSign, publicEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            // decrypt with private key
            var privateEncryptionKey = encryptionCertificate.PrivateKey as RSACryptoServiceProvider;
            var decryptedPayload = Jose.JWT.Decode(encryptedPayload, privateEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);


            // test encryption/signing combo
            var payloadToEncryptAndSign = new Dictionary<string, object>()
            {
                { "sub", "encryptedAndSignedkevin" },
                { "exp", 1300819380 }
            };

            var payloadToEncryptAndSign_encrypted =
                Jose.JWT.Encode(payloadToEncryptAndSign, publicEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            var payloadToEncryptAndSign_encryptedandsigned =
                Jose.JWT.Encode(payloadToEncryptAndSign_encrypted, privateSigningKey, JwsAlgorithm.RS256);

            var payloadToEncryptAndSign_encryptedandsigned_decoded =
                Jose.JWT.Decode(payloadToEncryptAndSign_encryptedandsigned, publicSigningKey);

            var payloadToEncryptAndSign_encryptedandsigned_decodeddecrypted =
                Jose.JWT.Decode(payloadToEncryptAndSign_encryptedandsigned_decoded, privateEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);


            var payloadToSignAndEncrypt = new Dictionary<string, object>()
            {
                { "sub", "signedAndEncryptedkevin" },
                { "exp", 1300819380 }
            };

            var payloadToSignAndEncrypt_encrypted =
                Jose.JWT.Encode(payloadToSignAndEncrypt, publicEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            var payloadToSignAndEncrypt_encryptedandsigned =
                Jose.JWT.Encode(payloadToSignAndEncrypt_encrypted, privateSigningKey, JwsAlgorithm.RS256);

            var payloadToSignAndEncrypt_encryptedandsigned_decoded =
                Jose.JWT.Decode(payloadToSignAndEncrypt_encryptedandsigned, publicSigningKey);

            var payloadToSignAndEncrypt_encryptedandsigned_decodeddecrypted =
                Jose.JWT.Decode(payloadToSignAndEncrypt_encryptedandsigned_decoded, privateEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);


            // get  thumbprint (kid), exponent (e) and modulus (n) (useful for generating jwkset)
            var rsaSigningKeyParameters = publicSigningKey.ExportParameters(false);
            var exponentSignAsString = Base64Url.Encode(rsaSigningKeyParameters.Exponent);
            var modulusSignAsString = Base64Url.Encode(rsaSigningKeyParameters.Modulus);
            var signingCertificateThumbprint = Convert.ToBase64String(signingCertificate.Export(X509ContentType.Cert));


            var rsaEncryptionKeyParameters = publicEncryptionKey.ExportParameters(false);
            var exponentEncryptasString = Base64Url.Encode(rsaEncryptionKeyParameters.Exponent);
            var modulusEncryptAsString = Base64Url.Encode(rsaEncryptionKeyParameters.Modulus);
            var encryptionCertificateThumbprint = Convert.ToBase64String(encryptionCertificate.Export(X509ContentType.Cert));


            return new string[] {
                $"Public signing key exponent: {exponentSignAsString}",
                $"Public signing key modulus: {modulusSignAsString}",
                $"Public signing certificate thumbprint: {signingCertificateThumbprint}",
                $"Public encryption key exponent: {exponentEncryptasString}",
                $"Public encryption key modulus: {modulusEncryptAsString}",
                $"Public encryption certificate thumbprint: {encryptionCertificateThumbprint}",
                "Encrypt first, sign later",
                payloadToEncryptAndSign_encrypted,
                payloadToEncryptAndSign_encryptedandsigned,
                payloadToEncryptAndSign_encryptedandsigned_decoded,
                payloadToEncryptAndSign_encryptedandsigned_decodeddecrypted,
                "Sign first, encrypt later",
                payloadToSignAndEncrypt_encrypted,
                payloadToSignAndEncrypt_encryptedandsigned,
                payloadToSignAndEncrypt_encryptedandsigned_decoded,
                payloadToSignAndEncrypt_encryptedandsigned_decodeddecrypted,
            };
        }
    }
}
