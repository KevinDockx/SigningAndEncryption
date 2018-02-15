using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Marvin.SigningAndEncryption.Core.Controllers
{

    /// <summary>
    /// Sign and encrypt data.  
    /// </summary>
    [Route("api/data")]
    public class SignAndEncryptDataController : Controller
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly X509Certificate2 _encryptionCertificate;

        private Dictionary<string, object> _data = new Dictionary<string, object>()
            {
                { "who", "Alice" },
                { "what", "in" },
                { "where", "Wonderland" }
            };

        public SignAndEncryptDataController()
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

        [HttpGet("createsignature")]
        public IActionResult CreateSignature()
        {
            var signature = string.Empty;
            var decodedData = string.Empty;
            var signatureIsValid = false;

            var serializedData = JsonConvert.SerializeObject(_data);
            byte[] signedDataAsByteArray;

            // sign with private key    
            using (var privateSigningKey = _signingCertificate.GetRSAPrivateKey())
            { 
                signedDataAsByteArray = privateSigningKey
                    .SignData(Encoding.Default.GetBytes(serializedData),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                              
                signature = Encoding.Default.GetString(signedDataAsByteArray);
            }

            // check signature with public key 
            using (var publicSigningKey = _signingCertificate.GetRSAPublicKey())
            {
                // Note that it is not possible to get the original data back from the signature.  
                // The signature is a hash of the original content, encrypted with the private key.  
                // You're not supposed to be able to get back the original content.  Decrypting
                // the signature would just give us the has of the original data.  This is by design. 
                signatureIsValid = publicSigningKey
                    .VerifyData(Encoding.Default.GetBytes(serializedData), signedDataAsByteArray,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss);               
            }
            
            return Json(new string[] {
                $"Original data: {serializedData}",
                $"Signature: {signature}",
                $"Signature is valid? {signatureIsValid}"
            }
            );
        }

        
        [HttpGet("encrypt")]
        public IActionResult EncryptData()
       {
            var encryptedData = string.Empty;
            var decryptedData = string.Empty;
            byte[] encryptedDataAsByteArray;
            
            var serializedData = JsonConvert.SerializeObject(_data);
            using (var publicEncryptionKey = _encryptionCertificate.GetRSAPublicKey())
            {
                // encrypt with public key.  Input must be byte[].
                encryptedDataAsByteArray = publicEncryptionKey
                .Encrypt(Encoding.Default.GetBytes(serializedData), RSAEncryptionPadding.OaepSHA256);

                encryptedData = Encoding.Default.GetString(encryptedDataAsByteArray);
            }

            using (var privateEncryptionKey = _encryptionCertificate.GetRSAPrivateKey())
            {
                // decrypt with private key    
                byte[] decryptedDataAsByteArray = privateEncryptionKey
                .Decrypt(encryptedDataAsByteArray, RSAEncryptionPadding.OaepSHA256);

                decryptedData = Encoding.Default.GetString(decryptedDataAsByteArray);
            }

            return Json(new string[] {
                $"Original data: {serializedData}",
                $"Encrypted data: {encryptedData}",
                $"Decrypted data: {decryptedData}"
            }
            );
        }

        [HttpGet("signandencryptdata")] 
        public IActionResult SignAndEncryptData()
        {
            throw new NotImplementedException();
        }

        [HttpGet("encryptandsigndata")]  
        public IActionResult EncryptAndSignData()
        {
            throw new NotImplementedException();
        }
    }    
}
