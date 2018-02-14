using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Marvin.SigningAndEncryption.Controllers
{
    [Route("api/jwkset")]
    public class JwkSetController : Controller
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly X509Certificate2 _encryptionCertificate;

        public JwkSetController()
        {
            _signingCertificate = new X509Certificate2(
                @"Certificates\test-sign.pfx",
                "Test",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            _encryptionCertificate = new X509Certificate2(
                @"Certificates\test-encrypt.pfx",
                "Test",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }


        /// <summary>
        /// Generate a jwkset containing public keys for signing and
        /// encrypting.   
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Get()
        {
            // get Kid, Exponent and Modulus
            var exportedSigningCertificateThumbprint = _signingCertificate.Thumbprint;
            var rsaSigningKeyParameters = (_signingCertificate.PublicKey.Key as RSACryptoServiceProvider)
                .ExportParameters(false);

            var exponentSignAsString = Base64Url.Encode(rsaSigningKeyParameters.Exponent);
            var modulusSignAsString = Base64Url.Encode(rsaSigningKeyParameters.Modulus);

            // signing keypair
            var signingKeyPair = new JwkKeyPair()
            {
                Alg = "RS256",
                E = exponentSignAsString,
                Use = "sig",
                Kid = exportedSigningCertificateThumbprint,
                Kty = "RSA",
                N = modulusSignAsString
            };

            // get Kid, Exponent and Modulus
            var exportedEncryptionCertificateThumbprint = _encryptionCertificate.Thumbprint;
            var rsaEncryptionKeyParameters = (_encryptionCertificate.PublicKey.Key as RSACryptoServiceProvider)
               .ExportParameters(false);
            
            var exponentEncryptAsString = Base64Url.Encode(rsaEncryptionKeyParameters.Exponent);
            var modulusEncryptAsString = Base64Url.Encode(rsaEncryptionKeyParameters.Modulus);

            // encryption keypair
            var encryptionKeyPair = new JwkKeyPair()
            {
                Alg = "RS256",
                E = exponentEncryptAsString,
                Use = "enc",
                Kid = exportedEncryptionCertificateThumbprint,
                Kty = "RSA",
                N = modulusEncryptAsString
            };

            var jwkKeyPairSet = new JwkKeyPairSet();
            jwkKeyPairSet.Keys.Add(signingKeyPair);
            jwkKeyPairSet.Keys.Add(encryptionKeyPair);

            return Json(jwkKeyPairSet);
        }
    }
}