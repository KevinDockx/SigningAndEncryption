using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Marvin.SigningAndEncryption.Core.Controllers
{

    [Route("api/signencrypt")]
    public class SignEncryptController : Controller
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly X509Certificate2 _encryptionCertificate;
        
        public SignEncryptController()
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

        [HttpGet("signtoken")]
        public IActionResult SignToken()
        {
            throw new NotImplementedException();
        }

        [HttpGet("encrypttoken")]
        public IActionResult EncryptToken()
       {
            var encryptedToken = string.Empty;
            var decryptedToken = string.Empty;
            byte[] encryptedTokenAsByteArray;

            // TODO: encoding issue 
            var token = "test";

            using (var publicEncryptionKey = _encryptionCertificate.GetRSAPublicKey())
            {
                // encrypt with public key.  Input must be byte[].
                encryptedTokenAsByteArray = publicEncryptionKey
                .Encrypt(Convert.FromBase64String(token), RSAEncryptionPadding.OaepSHA256);
                encryptedToken = Convert.ToBase64String(encryptedTokenAsByteArray);
            }

            using (var privateEncryptionKey = _encryptionCertificate.GetRSAPrivateKey())
            {
                // decrypt with private key    
                byte[] decryptedTokenAsByteArray = privateEncryptionKey
                .Decrypt(encryptedTokenAsByteArray, RSAEncryptionPadding.OaepSHA256);
                decryptedToken = Convert.ToBase64String(decryptedTokenAsByteArray);
            }

            return Json(new string[] {
                $"Original token: {token}",
                $"Encrypted token: {encryptedToken}",
                $"Decrypted token: {decryptedToken}"
            }
            );
        }

        [HttpGet("signandencrypttoken")] 
        public IActionResult SignAndEncryptToken()
        {
            throw new NotImplementedException();
        }

        [HttpGet("encryptandsigntoken")]  
        public IActionResult EncryptAndSignToken()
        {
            throw new NotImplementedException();
        }
    }    
}
