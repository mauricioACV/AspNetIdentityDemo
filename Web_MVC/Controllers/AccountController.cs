using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Web_MVC.Models;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;

namespace Web_MVC.Controllers
{
    public class AccountController : Controller
    {
        Models.IdentityEntities contexto = new Models.IdentityEntities();

        // GET: Account
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUral = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Models.LoginViewModel data, string returnUrl)
        {
            ActionResult Result;

            string clave = Models.Funciones.Encrypt(data.Password);
            RepositorioGenerico.Repositorio<Models.Usuario> Usuario = new RepositorioGenerico.Repositorio<Models.Usuario>(contexto);

            var User = Usuario.Retrieve(x => x.Email == data.Email && x.Clave == clave, "Usuario_Rol", "Usuario_Rol.Rol");

            if(User != null)
            {
                Result = SignInUser(User, data.RememberMe, returnUrl);
            }
            else
            {
                Result = View(data);
            }

            return Result;
        }

        private ActionResult SignInUser(Usuario user, bool rememberMe, string returnUrl)
        {
            ActionResult Result;

            List<Claim> Claims = new List<Claim>();
            Claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            Claims.Add(new Claim(ClaimTypes.Email, user.Email));
            Claims.Add(new Claim(ClaimTypes.Name, user.Nombres));

            Claims.Add(new Claim("FullName", $"{user.Nombres} {user.Apellidos}"));

            if(user.Usuario_Rol != null && user.Usuario_Rol.Any())
            {
                Claims.AddRange(user.Usuario_Rol.Select(x => new Claim(ClaimTypes.Role, x.Rol.Nombre)));
            }

            var Identity = new ClaimsIdentity(Claims, DefaultAuthenticationTypes.ApplicationCookie);

            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;

            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = rememberMe }, Identity);

            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                returnUrl = Url.Action("Index", "Home");
            }

            Result = Redirect(returnUrl);

            return Result;
        }

        public ActionResult LogOff()
        {
            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;

            authenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            return RedirectToAction("Index", "Home");
        }
    }
}