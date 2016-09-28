using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace ConsoleApplication
{
    public class Program
    {
        private static readonly byte[] _helloWorldPayload = Encoding.UTF8.GetBytes("Hello, World!");
        
        public static void Main(string[] args)
        {
            SecurityKey key;
            string algorithm;

            // https://tools.ietf.org/html/rfc7518#section-3
            if (args.Length == 1 && args[0].Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase)) {
                key = new SymmetricSecurityKey(new HMACSHA256().Key);
                algorithm = SecurityAlgorithms.HmacSha256;
            }
            else if (args.Length == 1 && args[0].Equals(SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase)) {
                var rsa = RSA.Create();
                rsa.KeySize = 2048;
                key = new RsaSecurityKey(rsa);
                algorithm = SecurityAlgorithms.RsaSha256;                
            }
            else if (args.Length == 1 && args[0].Equals(SecurityAlgorithms.EcdsaSha256, StringComparison.OrdinalIgnoreCase)) {
                var ecdsa = ECDsa.Create();
                ecdsa.KeySize = 256;
                key = new ECDsaSecurityKey(ecdsa);
                algorithm = SecurityAlgorithms.EcdsaSha256;                
            }
            else {
                Console.WriteLine($"PlaintextJwtAuth.exe [{SecurityAlgorithms.HmacSha256}|{SecurityAlgorithms.RsaSha256}|{SecurityAlgorithms.EcdsaSha256}]");
                return;
            }

            new WebHostBuilder()
                .UseUrls("http://+:5000")
                .UseKestrel()
                .ConfigureServices(services => {
                    services.AddAuthentication();
                })                
                .Configure(app => {
                    app.UseJwtBearerAuthentication(new JwtBearerOptions()
                    {
                        TokenValidationParameters = new TokenValidationParameters()
                        {
                            ValidAudience = "TestAudience",
                            ValidIssuer = "TestIssuer",
                            IssuerSigningKey = key
                        }
                    });

                    app.Run(async context =>
                    {
                        context.Response.StatusCode = 200;
                        context.Response.ContentType = "text/plain";

                        if (context.User.Identity.IsAuthenticated) {
                            context.Response.Headers["Content-Length"] = "13";
                            await context.Response.Body.WriteAsync(_helloWorldPayload, 0, _helloWorldPayload.Length);
                        }
                        else {
                            var handler = new JwtSecurityTokenHandler();
                            var token = handler.WriteToken(handler.CreateJwtSecurityToken(new SecurityTokenDescriptor() {
                                Audience = "TestAudience",
                                Issuer = "TestIssuer",
                                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "TestName") }, JwtBearerDefaults.AuthenticationScheme),
                                SigningCredentials = new SigningCredentials(key, algorithm)
                            }));
                            
                            var response = "Authorization: Bearer " + token;
                            var responseBytes = Encoding.UTF8.GetBytes(response); 

                            context.Response.ContentLength = responseBytes.Length;
                            await context.Response.Body.WriteAsync(responseBytes, 0, responseBytes.Length);
                        }
                    });
                })
                .Build()
                .Run();
        }
    }
}
