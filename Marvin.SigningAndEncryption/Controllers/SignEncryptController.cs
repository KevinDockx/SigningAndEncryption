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
        private readonly X509Certificate2 signingCertificate;
        private readonly X509Certificate2 encryptionCertificate;
        private readonly RSACryptoServiceProvider publicSigningKey;
        private readonly RSACryptoServiceProvider privateSigningKey;
        private readonly RSACryptoServiceProvider publicEncryptionKey;
        private readonly RSACryptoServiceProvider privateEncryptionKey;

        public SignEncryptController()
        {
            signingCertificate = new X509Certificate2(@"Certificates\test-sign.pfx", "Test",
              X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
            encryptionCertificate = new X509Certificate2(@"Certificates\test-encrypt.pfx", "Test",
             X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            publicSigningKey = signingCertificate.PublicKey.Key as RSACryptoServiceProvider;
            privateSigningKey = signingCertificate.PrivateKey as RSACryptoServiceProvider;          

            publicEncryptionKey = encryptionCertificate.PublicKey.Key as RSACryptoServiceProvider;
            privateEncryptionKey = encryptionCertificate.PrivateKey as RSACryptoServiceProvider;
        }


        // GET api/values
        [HttpGet]
        public IActionResult Get()
        {
            var tokenToSign = new Dictionary<string, object>()
            {
                { "sub", "signedkevin" },
                { "exp", 1300819380 }
            };

            // TEST signing

            // sign with private key, check signature with public key (you can also check the signature
            // with the private key of course, but that one shouldn't be given away ;))
            var signedToken = Jose.JWT.Encode(tokenToSign, privateSigningKey, JwsAlgorithm.RS256);
            var decodedToken = Jose.JWT.Decode(signedToken, publicSigningKey);

            // TEST encryption
            // encrypt with the public key, decrypt with the private key

            var tokenToEncrypt = new Dictionary<string, object>()
            {
                { "sub", "encryptedkevin" },
                { "exp", 1300819380 }
            };

            // encrypt with public key
            var encryptedToken = Jose.JWT.Encode(tokenToSign, publicEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            // decrypt with private key           
            var decryptedToken = Jose.JWT.Decode(encryptedToken, privateEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);


            // test encryption/signing combo
            var tokenToEncryptAndSign = new Dictionary<string, object>()
            {
                { "sub", "encryptedAndSignedkevin" },
                { "exp", 1300819380 }
            };

            var tokenToEncryptAndSign_encrypted =
                Jose.JWT.Encode(tokenToEncryptAndSign, publicEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            var tokenToEncryptAndSign_encryptedandsigned =
                Jose.JWT.Encode(tokenToEncryptAndSign_encrypted, privateSigningKey, JwsAlgorithm.RS256);

            var tokenToEncryptAndSign_encryptedandsigned_decoded =
                Jose.JWT.Decode(tokenToEncryptAndSign_encryptedandsigned, publicSigningKey);

            var tokenToEncryptAndSign_encryptedandsigned_decodeddecrypted =
                Jose.JWT.Decode(tokenToEncryptAndSign_encryptedandsigned_decoded, privateEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);


            var tokenToSignAndEncrypt = new Dictionary<string, object>()
            {
                { "sub", "signedAndEncryptedkevin" },
                { "exp", 1300819380 }
            };

            var tokenToSignAndEncrypt_encrypted =
                Jose.JWT.Encode(tokenToSignAndEncrypt, publicEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            var tokenToSignAndEncrypt_encryptedandsigned =
                Jose.JWT.Encode(tokenToSignAndEncrypt_encrypted, privateSigningKey, JwsAlgorithm.RS256);

            var tokenToSignAndEncrypt_encryptedandsigned_decoded =
                Jose.JWT.Decode(tokenToSignAndEncrypt_encryptedandsigned, publicSigningKey);

            var tokenToSignAndEncrypt_encryptedandsigned_decodeddecrypted =
                Jose.JWT.Decode(tokenToSignAndEncrypt_encryptedandsigned_decoded, privateEncryptionKey,
                JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);


            // get  thumbprint (kid), exponent (e) and modulus (n) (useful for generating jwkset)
            var rsaSigningKeyParameters = publicSigningKey.ExportParameters(false);
            var exponentSignAsString = Base64Url.Encode(rsaSigningKeyParameters.Exponent);
            var modulusSignAsString = Base64Url.Encode(rsaSigningKeyParameters.Modulus);
            var signingCertificateThumbprint = signingCertificate.Thumbprint;


            var rsaEncryptionKeyParameters = publicEncryptionKey.ExportParameters(false);
            var exponentEncryptasString = Base64Url.Encode(rsaEncryptionKeyParameters.Exponent);
            var modulusEncryptAsString = Base64Url.Encode(rsaEncryptionKeyParameters.Modulus);
            var encryptionCertificateThumbprint = encryptionCertificate.Thumbprint;


            return Json(new string[] {
                $"Public signing key exponent: {exponentSignAsString}",
                $"Public signing key modulus: {modulusSignAsString}",
                $"Public signing certificate thumbprint: {signingCertificateThumbprint}",
                $"Public encryption key exponent: {exponentEncryptasString}",
                $"Public encryption key modulus: {modulusEncryptAsString}",
                $"Public encryption certificate thumbprint: {encryptionCertificateThumbprint}",
                "Encrypt first, sign later",
                tokenToEncryptAndSign_encrypted,
                tokenToEncryptAndSign_encryptedandsigned,
                tokenToEncryptAndSign_encryptedandsigned_decoded,
                tokenToEncryptAndSign_encryptedandsigned_decodeddecrypted,
                "Sign first, encrypt later",
                tokenToSignAndEncrypt_encrypted,
                tokenToSignAndEncrypt_encryptedandsigned,
                tokenToSignAndEncrypt_encryptedandsigned_decoded,
                tokenToSignAndEncrypt_encryptedandsigned_decodeddecrypted,
            });
        }
    }
}
