using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

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
                .Configure(app => {
                    app.Run(context =>
                    {
                        context.Response.StatusCode = 200;
                        context.Response.ContentType = "text/plain";
                        context.Response.Headers["Content-Length"] = "13";
                        return context.Response.Body.WriteAsync(_helloWorldPayload, 0, _helloWorldPayload.Length);
                    });
                })
                .Build()
                .Run();
        }
    }
}
