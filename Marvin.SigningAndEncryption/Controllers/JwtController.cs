using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Marvin.SigningAndEncryption.Controllers
{
    [Route("api/jwt")]
    public class JwtController : Controller
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly X509Certificate2 _encryptionCertificate;
        private readonly RSACryptoServiceProvider _publicSigningKey;
        private readonly RSACryptoServiceProvider _privateSigningKey;
        private readonly RSACryptoServiceProvider _publicEncryptionKey;
        private readonly RSACryptoServiceProvider _privateEncryptionKey;

        private Dictionary<string, object> _token = new Dictionary<string, object>()
            {
                { "sub", "kevin" },
                { "exp", 1300819380 }
            };

        public JwtController()
        {
            _signingCertificate = new X509Certificate2(
                @"Certificates\test-sign.pfx",
                "Test",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            _encryptionCertificate = new X509Certificate2(
                @"Certificates\test-encrypt.pfx",
                "Test",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            _publicSigningKey = _signingCertificate.PublicKey.Key as RSACryptoServiceProvider;
            _privateSigningKey = _signingCertificate.PrivateKey as RSACryptoServiceProvider;

            _publicEncryptionKey = _encryptionCertificate.PublicKey.Key as RSACryptoServiceProvider;
            _privateEncryptionKey = _encryptionCertificate.PrivateKey as RSACryptoServiceProvider;
        }

        [HttpGet("sign")]
        public IActionResult SignToken()
        {
            // sign with private key
            var signedToken = Jose.JWT.Encode(_token, _privateSigningKey, Jose.JwsAlgorithm.RS256);

            // check signature with public key (you can also check the signature
            // with the private key of course, but that one shouldn't be given away ;))
            var decodedToken = Jose.JWT.Decode(signedToken, _publicSigningKey);

            return Json(new string[] {
                $"Original token: {JsonConvert.SerializeObject(_token)}",
                $"Signed token: {signedToken}",
                $"Decoded token: {decodedToken}"
            }
            );
        }

        [HttpGet("encrypt")]
        public IActionResult EncryptToken()
        {
            // encrypt with public key
            var encryptedToken = Jose.JWT.Encode(_token, _publicEncryptionKey,
                Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A128CBC_HS256);

            // decrypt with private key           
            var decryptedToken = Jose.JWT.Decode(encryptedToken, _privateEncryptionKey,
                Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A128CBC_HS256);

            return Json(new string[] {
                $"Original token: {JsonConvert.SerializeObject(_token)}",
                $"Encrypted token: {encryptedToken}",
                $"Decrypted token: {decryptedToken}"
            }
            );
        }

        [HttpGet("signandencrypt")]
        public IActionResult SignAndEncryptToken()
        {
            var signedToken =
                Jose.JWT.Encode(_token, _privateSigningKey, Jose.JwsAlgorithm.RS256);

            var signedAndEncryptedToken = Jose.JWT.Encode(signedToken, _publicEncryptionKey,
                Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A128CBC_HS256);

            var signedAndDecryptedToken =
                  Jose.JWT.Decode(signedAndEncryptedToken, _privateEncryptionKey,
                Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A128CBC_HS256);

            var decodedAndDecryptedToken =
                Jose.JWT.Decode(signedAndDecryptedToken, _publicSigningKey);

            return Json(new string[] {
                $"Original token: {JsonConvert.SerializeObject(_token)}",
                $"Signed token: {signedToken}",
                $"Signed and encrypted token: {signedAndEncryptedToken}",
                $"Signed and decrypted token: {signedAndDecryptedToken}",
                $"Decoded and decrypted token: {decodedAndDecryptedToken}"
            });
        }

        [HttpGet("encryptandsign")]
        public IActionResult EncryptAndSignToken()
        {
            var encryptedToken =
             Jose.JWT.Encode(_token, _publicEncryptionKey,
             Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A128CBC_HS256);

            var encryptedAndSignedToken =
                Jose.JWT.Encode(encryptedToken, _privateSigningKey, Jose.JwsAlgorithm.RS256);

            var encryptedAndDecodedToken =
                Jose.JWT.Decode(encryptedAndSignedToken, _publicSigningKey);

            var decryptedAndDecodedToken =
                Jose.JWT.Decode(encryptedAndDecodedToken, _privateEncryptionKey,
                Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A128CBC_HS256);

            return Json(new string[] {
                $"Original token: {JsonConvert.SerializeObject(_token)}",
                $"Encrypted token: {encryptedToken}",
                $"Encrypted and signed token: {encryptedAndSignedToken}",
                $"Encrypted and decoded token: {encryptedAndDecodedToken}",
                $"Decrypted and decoded token: {decryptedAndDecodedToken}"
            }
            );
        }
    }
}
