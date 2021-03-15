using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Web_MVC.Models;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Web_MVC.Helpers;
using System.Threading.Tasks;
using RepositorioGenerico;

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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLinkLogin(string provider, string returnUrl)
        {
            string UserID = null;
            // Obtenemos el identificador del usuario autenticado
            if (this.User.Identity.IsAuthenticated && User is ClaimsPrincipal)
            {
                var Identity = User as ClaimsPrincipal;
                var Claims = Identity.Claims.ToList();
                UserID = Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;
            }
            // Solicitamos un Redirect al proveedor externo
            return new ChallengeResult(provider, Url.Action(
                "ExternalLinkLoginCallback", "Account", new { ReturnUrl = returnUrl }), UserID);
        }

        public async Task<ActionResult> ExternalLinkLoginCallback()
        {
            ActionResult Result;
            // Obtener la información devuelta por el proveedor externo
            var LoginInfo =
                await HttpContext.GetOwinContext().
                Authentication.GetExternalLoginInfoAsync(
                    ChallengeResult.XsrfKey, User.Identity.GetUserId());

            if (LoginInfo == null)
                Result = Content("No se pudo realizar la autenticación con el proveedor externo");
            else
            {
                // El usuario ha sido autenticado por el proveedor externo!
                // Obtener la llave del proveedor de autenticación.
                // Esta llave es específica del usuario.
                string ProviderKey = LoginInfo.Login.ProviderKey;
                // Obtener el nombre del proveedor de autenticación.
                string ProviderName = LoginInfo.Login.LoginProvider;
                // Enlazar los datos de la cuenta externa con la cuenta de usuario local. 
                int IdUsuario = int.Parse(Funciones.GetClaimInfo(ClaimTypes.NameIdentifier));
                //User.Identity.GetUserId<int>()
                Repositorio<Usuario> Usuario = new Repositorio<Usuario>(contexto);
                Repositorio.Excepcion += Repositorio_Excepcion;
                Usuario.Update(x => x.Id == IdUsuario, "ProviderKey", ProviderKey);
                Usuario.Update(x => x.Id == IdUsuario, "ProviderName", ProviderName);
                Repositorio.Excepcion -= Repositorio_Excepcion;
                Result = Content($"Se ha enlazado la cuenta local con la cuenta de {ProviderName}");
            }
            return Result;
        }

        private void Repositorio_Excepcion(object sender, ExceptionEvenArgs e)
        {

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Solicitamos un Redirect al proveedor externo.
            return new
                ChallengeResult(provider, Url.Action(
                    "ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            ActionResult Result;

            // Obtener la información devuelta por el proveedor externo
            var LoginInfo = await HttpContext.GetOwinContext().
                Authentication.GetExternalLoginInfoAsync();

            if (LoginInfo == null)
                // No se pudo autenticar.
                Result = RedirectToAction("Login");
            else
            {
                // El usuario ha sido autenticado por el proveedor externo!
                // Obtener la llave del proveedor que identifica al usuario.
                string ProviderKey = LoginInfo.Login.ProviderKey;
                // Buscar al usuario
                Repositorio<Usuario> Usuario = new Repositorio<Usuario>(contexto);

                var User = Usuario.Retrieve(x => x.ProviderKey == ProviderKey);
                if (User != null)// Se ha encontrado al usuario. Iniciar la sesión del usuario.                    
                    Result = SignInUser(User, false, returnUrl);
                else
                    Result = Content($"Imposible iniciar sesión con {LoginInfo.Login.LoginProvider}");
            }
            return Result;
        }


    }
}