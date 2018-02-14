# Samples for Signing and Encrypting Data/Tokens and Generating a JwkSet

When implementing extended OAuth/OIDC client authentication mechanisms (eg private_key_jwt) you'll often have to generate a JwkSet.  That keyset can then be used by an IDP to decode signed tokens with a public key from the JwkSet, or to encrypt tokens/data with a public key.  This sample shows you how to create such a JwkSet.

The samples are based on ASP.NET Core.  Marvin.SigningAndEncryption is an ASP.NET Core project targeting .NET 4.6.1.  Marvin.SigningAndEncryption.Core targets .NET Core 2.0.

Next to that, these samples show you how to encrypt, decrypt, sign and decode tokens/other data.  

You can access the various encryption/decryption/signing/decoding samples from api/signencrypt.  

Not everything has been implememented yet.  Check the issue list.
