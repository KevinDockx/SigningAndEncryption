using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Marvin.SigningAndEncryption.Core.Controllers
{

    [Route("api/signencrypt")]
    public class SignEncryptController : Controller
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly X509Certificate2 _encryptionCertificate;

        private Dictionary<string, object> token = new Dictionary<string, object>()
            {
                { "sub", "kevin" },
                { "exp", 1300819380 }
            };

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
            
            var serializedToken = JsonConvert.SerializeObject(token);
            using (var publicEncryptionKey = _encryptionCertificate.GetRSAPublicKey())
            {
                // encrypt with public key.  Input must be byte[].
                encryptedTokenAsByteArray = publicEncryptionKey
                .Encrypt(Encoding.UTF8.GetBytes(serializedToken), RSAEncryptionPadding.OaepSHA256);

                encryptedToken = Encoding.UTF8.GetString(encryptedTokenAsByteArray);
            }

            using (var privateEncryptionKey = _encryptionCertificate.GetRSAPrivateKey())
            {
                // decrypt with private key    
                byte[] decryptedTokenAsByteArray = privateEncryptionKey
                .Decrypt(encryptedTokenAsByteArray, RSAEncryptionPadding.OaepSHA256);

                decryptedToken = Encoding.UTF8.GetString(decryptedTokenAsByteArray);
            }

            return Json(new string[] {
                $"Original token: {serializedToken}",
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
