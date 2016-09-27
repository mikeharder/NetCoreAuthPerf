using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace ConsoleApplication
{
    public class Program
    {
        private static readonly byte[] _helloWorldPayload = Encoding.UTF8.GetBytes("Hello, World!");
        private static readonly byte[] _helloNoauthPayload = Encoding.UTF8.GetBytes("Hello, Noauth");
        
        public static void Main(string[] args)
        {
            new WebHostBuilder()
                .UseUrls("http://+:5000")
                .UseKestrel()
                .ConfigureServices(services => {
                    services.AddAuthentication();
                })
                .Configure(app => {
                    app.UseCookieAuthentication();

                    app.Run(context =>
                    {
                        context.Response.StatusCode = 200;
                        context.Response.ContentType = "text/plain";
                        context.Response.Headers["Content-Length"] = "13";

                        if (context.User.Identity.IsAuthenticated) {
                            return context.Response.Body.WriteAsync(_helloWorldPayload, 0, _helloWorldPayload.Length);
                        }
                        else {
                            var user = new ClaimsPrincipal(
                                new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "test")}, CookieAuthenticationDefaults.AuthenticationScheme));
                            
                            return context.Authentication.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user)
                                .ContinueWith((_) => context.Response.Body.WriteAsync(_helloNoauthPayload, 0, _helloNoauthPayload.Length));
                        }
                    });
                })
                .Build()
                .Run();
        }
    }
}
