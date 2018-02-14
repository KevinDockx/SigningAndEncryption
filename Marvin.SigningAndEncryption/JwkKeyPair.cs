using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Marvin.SigningAndEncryption
{
    public class JwkKeyPair
    {
        /// <summary>
        /// Key type (RSA, EC)
        /// </summary>
        public string Kty { get; set; }


        /// <summary>
        /// Public key exponent 
        /// </summary>
        public string E { get; set; }

        /// <summary>
        /// Keypair use: sig (signing), enc (encoding)
        /// </summary>
        public string Use { get; set; }

        /// <summary>
        /// Key(pair) ID
        /// </summary>
        public string Kid { get; set; }

        /// <summary>
        /// Algorithm intended for use with the key (eg: RS256)
        /// </summary>

        public string Alg { get; set; }

        /// <summary>
        ///  The public key modulus
        /// </summary>
        public string N { get; set; }
    }
}
