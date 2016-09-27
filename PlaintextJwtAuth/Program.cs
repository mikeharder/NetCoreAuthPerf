﻿using System;
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
            new WebHostBuilder()
                .UseUrls("http://+:5000")
                .UseKestrel()
                .ConfigureServices(services => {
                    services.AddAuthentication();
                })                
                .Configure(app => {
                    var key = new SymmetricSecurityKey(new HMACSHA256().Key);

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
                                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
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
