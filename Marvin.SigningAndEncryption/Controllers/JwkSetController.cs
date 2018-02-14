using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Marvin.SigningAndEncryption.Controllers
{
    public class JwkSetController
    {
        [HttpGet]
        public string Get()
        {
            // generate a jwkset containing public keys for signing and
            // encrypting.   

            var signingCertificate = new X509Certificate2(@"Certificates\test-sign.pfx", "Test",
              X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            var exportedSigningCertificateThumbprint = signingCertificate.Thumbprint;

            var rsaSigningKeyParameters = (signingCertificate.PublicKey.Key as RSACryptoServiceProvider)
                .ExportParameters(false);

            // get exponent and modulus 
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
            
            var encryptionCertificate = new X509Certificate2(@"Certificates\test-encrypt.pfx", "Test",
             X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            var exportedEncryptionCertificatePublicKey =
            Convert.ToBase64String(encryptionCertificate.Export(X509ContentType.Cert));

            var exportedEncryptionCertificateThumbprint = encryptionCertificate.Thumbprint;

            var rsaEncryptionKeyParameters = (encryptionCertificate.PublicKey.Key as RSACryptoServiceProvider)
               .ExportParameters(false);

            // get exponent and modulus 
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

            var camelCaseFormatter = new JsonSerializerSettings();
            camelCaseFormatter.ContractResolver = new CamelCasePropertyNamesContractResolver();
            return JsonConvert.SerializeObject(jwkKeyPairSet, camelCaseFormatter);
        }
    }
}