using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace JwtCommon
{
    public static class JwtKeyGenerator
    {
        public static KeyAndAlgorithm GetKeyAndAlgorithm(string[] args)
        {
            // https://tools.ietf.org/html/rfc7518#section-3
            if (args.Length >= 1 && args[0].Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
            {
                return new KeyAndAlgorithm()
                {
                    Key = new SymmetricSecurityKey(new HMACSHA256().Key),
                    Algorithm = SecurityAlgorithms.HmacSha256,
                    AlgorithmDescription = SecurityAlgorithms.HmacSha256
                };
            }
            else if (args.Length >= 1 && args[0].Equals(SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase))
            {
                var keyAndAlgorithm = new KeyAndAlgorithm() {
                    Algorithm = SecurityAlgorithms.RsaSha256,
                    AlgorithmDescription = SecurityAlgorithms.RsaSha256
                };

                RSA rsa;
                if (args.Length >= 2 && args[1].Equals("newcsp", StringComparison.OrdinalIgnoreCase))
                {
                    rsa = new RSACryptoServiceProvider(2048);
                    keyAndAlgorithm.AlgorithmDescription += " [new RSACryptoServiceProvider()]";
                }
                else if (args.Length >= 2 && args[1].Equals("newcng", StringComparison.OrdinalIgnoreCase)) {
                    rsa = new RSACng(2048);
                    keyAndAlgorithm.AlgorithmDescription += " [new RSACng(2048)]";
                }
                else
                {
                    rsa = RSA.Create();
                    rsa.KeySize = 2048;
                    keyAndAlgorithm.AlgorithmDescription += " [RSA.Create()]";
                }
                keyAndAlgorithm.Key = new RsaSecurityKey(rsa);
                return keyAndAlgorithm;
            }
            else if (args.Length >= 1 && args[0].Equals(SecurityAlgorithms.EcdsaSha256, StringComparison.OrdinalIgnoreCase))
            {
                var keyAndAlgorithm = new KeyAndAlgorithm()
                {
                    Algorithm = SecurityAlgorithms.EcdsaSha256,
                    AlgorithmDescription = SecurityAlgorithms.EcdsaSha256
                };

                ECDsa ecdsa;
                if (args.Length >= 2 && args[1].Equals("newcng", StringComparison.OrdinalIgnoreCase))
                {
                    ecdsa = new ECDsaCng(256);
                    keyAndAlgorithm.AlgorithmDescription += " [new ECDsaCng()]";
                }
                else
                {
                    ecdsa = ECDsa.Create();
                    ecdsa.KeySize = 256;
                    keyAndAlgorithm.AlgorithmDescription += " [ECDsa.Create()]";
                }

                keyAndAlgorithm.Key = new ECDsaSecurityKey(ecdsa);
                return keyAndAlgorithm;
            }
            else
            {
                return null;
            }
        }

        public static string HelpString =>
            $"[{SecurityAlgorithms.HmacSha256}|{SecurityAlgorithms.RsaSha256}|{SecurityAlgorithms.EcdsaSha256}] [create|newcsp|newcng]";
    }
}
