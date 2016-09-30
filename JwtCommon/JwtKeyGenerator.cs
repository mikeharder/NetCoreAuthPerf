using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Linq;

namespace JwtCommon
{
    public static class JwtKeyGenerator
    {
        public static KeyAndAlgorithm GetKeyAndAlgorithm(string[] args)
        {
            // https://tools.ietf.org/html/rfc7518#section-3
            if (args.Contains(SecurityAlgorithms.HmacSha256, StringComparer.OrdinalIgnoreCase))
            {
                var key = new SymmetricSecurityKey(new HMACSHA256().Key);
                return new KeyAndAlgorithm()
                {
                    SigningKey = key,
                    ValidationKey = key,
                    Algorithm = SecurityAlgorithms.HmacSha256,
                    AlgorithmDescription = SecurityAlgorithms.HmacSha256
                };
            }
            else if (args.Contains(SecurityAlgorithms.RsaSha256, StringComparer.OrdinalIgnoreCase))
            {
                var keyAndAlgorithm = new KeyAndAlgorithm() {
                    Algorithm = SecurityAlgorithms.RsaSha256,
                    AlgorithmDescription = SecurityAlgorithms.RsaSha256
                };

                RSA rsa;
                if (args.Contains("newcsp", StringComparer.OrdinalIgnoreCase))
                {
                    rsa = new RSACryptoServiceProvider(2048);
                    keyAndAlgorithm.AlgorithmDescription += " [new RSACryptoServiceProvider()]";
                }
                else if (args.Contains("newcng", StringComparer.OrdinalIgnoreCase)) {
                    rsa = new RSACng(2048);
                    keyAndAlgorithm.AlgorithmDescription += " [new RSACng(2048)]";
                }
                else
                {
                    rsa = RSA.Create();                   
                    rsa.KeySize = 2048;
                    keyAndAlgorithm.AlgorithmDescription += " [RSA.Create()";
                }

                keyAndAlgorithm.SigningKey = new RsaSecurityKey(rsa);

                if (args.Contains("params", StringComparer.OrdinalIgnoreCase))
                {
                    keyAndAlgorithm.ValidationKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false));
                    keyAndAlgorithm.AlgorithmDescription += ".ExportParameters(includePrivateParameters: false)]";
                }
                else
                {
                    keyAndAlgorithm.ValidationKey = new RsaSecurityKey(rsa);
                    keyAndAlgorithm.AlgorithmDescription += "]";
                }

                return keyAndAlgorithm;
            }
            else if (args.Contains(SecurityAlgorithms.EcdsaSha256, StringComparer.OrdinalIgnoreCase))
            {
                var keyAndAlgorithm = new KeyAndAlgorithm()
                {
                    Algorithm = SecurityAlgorithms.EcdsaSha256,
                    AlgorithmDescription = SecurityAlgorithms.EcdsaSha256
                };

                ECDsa ecdsa;
                if (args.Contains("newcng", StringComparer.OrdinalIgnoreCase))
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

                var key = new ECDsaSecurityKey(ecdsa);
                keyAndAlgorithm.SigningKey = key;
                keyAndAlgorithm.ValidationKey = key;
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
