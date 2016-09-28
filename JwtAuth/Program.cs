using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Threading;
using System.Diagnostics;

namespace ConsoleApplication
{
    public class Program
    {
        private static readonly int _threads = Environment.ProcessorCount;
        private static readonly TimeSpan _duration = TimeSpan.FromSeconds(10);
        private static long _validations = 0;

        public static int Main(string[] args)
        {
            var keyAndAlgorithm = GetKeyAndAlgorithm(args);
            if (keyAndAlgorithm == null)
            {
                Console.WriteLine($"JwtAuth.exe [{SecurityAlgorithms.HmacSha256}|{SecurityAlgorithms.RsaSha256}|{SecurityAlgorithms.EcdsaSha256}]");
                return 1;
            }

            var key = keyAndAlgorithm.Item1;
            var algorithm = keyAndAlgorithm.Item2;

            Console.WriteLine($"Duration: {_duration}");
            Console.WriteLine($"Algorithm: {algorithm}");

            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(handler.CreateJwtSecurityToken(new SecurityTokenDescriptor()
            {
                Audience = "TestAudience",
                Issuer = "TestIssuer",
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "TestName") }, JwtBearerDefaults.AuthenticationScheme),
                SigningCredentials = new SigningCredentials(key, algorithm)
            }));

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = "TestAudience",
                ValidIssuer = "TestIssuer",
                IssuerSigningKey = key
            };

            var sw = new Stopwatch();
            var threads = new Thread[_threads];
            for (var i=0; i < _threads; i++)
            {
                threads[i] = new Thread(() =>
                {
                    SecurityToken validatedToken;
                    ClaimsPrincipal claimsPrincipal = null;

                    while (sw.Elapsed < _duration)
                    {
                        claimsPrincipal = handler.ValidateToken(token, tokenValidationParameters, out validatedToken);
                        Interlocked.Increment(ref _validations);
                    }

                    if (claimsPrincipal.Identity.Name != "TestName")
                    {
                        throw new InvalidOperationException();
                    }
                });
            }

            sw.Start();
            for (var i=0; i < _threads; i++)
            {
                threads[i].Start();
            }

            for (var i = 0; i < _threads; i++)
            {
                threads[i].Join();
            }

            Console.WriteLine($"Total Validations: {_validations}");

            var validationsPerSecond = Math.Round(_validations / _duration.TotalSeconds, 0);
            Console.WriteLine($"Validations per Second: {validationsPerSecond}");

            return 0;
        }

        private static Tuple<SecurityKey, string> GetKeyAndAlgorithm(string[] args)
        {
            // https://tools.ietf.org/html/rfc7518#section-3
            if (args.Length == 1 && args[0].Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
            {
                return Tuple.Create<SecurityKey, string>(new SymmetricSecurityKey(new HMACSHA256().Key),
                    SecurityAlgorithms.HmacSha256);
            }
            else if (args.Length == 1 && args[0].Equals(SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase))
            {
                return Tuple.Create<SecurityKey, string>(new RsaSecurityKey(new RSACryptoServiceProvider(2048)),
                    SecurityAlgorithms.RsaSha256);
            }
            else if (args.Length == 1 && args[0].Equals(SecurityAlgorithms.EcdsaSha256, StringComparison.OrdinalIgnoreCase))
            {
                return Tuple.Create<SecurityKey, string>(new ECDsaSecurityKey(new ECDsaCng()),
                    SecurityAlgorithms.EcdsaSha256);
            }
            else
            {
                return null;
            }
        }
    }
}
