using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Marvin.SigningAndEncryption
{
    public class JwkKeyPairSet
    {
        public IList<JwkKeyPair> Keys { get; set; } = new List<JwkKeyPair>();
    }
}
