using JwtCommon;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;

namespace ConsoleApplication
{
    public class Program
    {
        private static readonly int _threads = Environment.ProcessorCount;
        private static readonly TimeSpan _duration = TimeSpan.FromSeconds(10);
        private static long _validations = 0;

        public static int Main(string[] args)
        {
            var keyAndAlgorithm = JwtKeyGenerator.GetKeyAndAlgorithm(args);
            if (keyAndAlgorithm == null)
            {
                Console.WriteLine($"JwtAuth.exe {JwtKeyGenerator.HelpString}");
                return 1;
            }
            
            Console.WriteLine($"Duration: {_duration}");
            Console.WriteLine($"Algorithm: {keyAndAlgorithm.AlgorithmDescription}");
            Console.WriteLine($"Key Size: {keyAndAlgorithm.ValidationKey.KeySize}");

            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(handler.CreateJwtSecurityToken(new SecurityTokenDescriptor()
            {
                Audience = "TestAudience",
                Issuer = "TestIssuer",
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "TestName") }, JwtBearerDefaults.AuthenticationScheme),
                SigningCredentials = new SigningCredentials(keyAndAlgorithm.SigningKey, keyAndAlgorithm.Algorithm)
            }));

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = "TestAudience",
                ValidIssuer = "TestIssuer",
                IssuerSigningKey = keyAndAlgorithm.ValidationKey
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

    }
}
