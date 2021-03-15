using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.AspNet.Identity;

[assembly: OwinStartup(typeof(Web_MVC.App_Start.Startup))]

namespace Web_MVC.App_Start
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888
            app.UseCookieAuthentication(new Microsoft.Owin.Security.Cookies.CookieAuthenticationOptions()
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/account/login")
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseFacebookAuthentication(appId: "1234", appSecret: "1234");
            
            app.UseGoogleAuthentication(clientId: "1234", clientSecret: "1234");

            app.UseMicrosoftAccountAuthentication(clientId: "1234", clientSecret: "1234");

            app.UseTwitterAuthentication(consumerKey: "1234", consumerSecret: "1234");
        }
    }
}
