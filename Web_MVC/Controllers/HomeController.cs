using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Claims;
using System.Threading;

namespace Web_MVC.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        // GET: Home
        [AllowAnonymous]
        public ActionResult Index()
        {
            ClaimsPrincipal Principal = Thread.CurrentPrincipal as ClaimsPrincipal;

            //ClaimsPrincipal Principal2 = HttpContext.User as ClaimsPrincipal;

            //ClaimsPrincipal Principal3 = this.User as ClaimsPrincipal;

            if (Principal != null && Principal.Identity.IsAuthenticated)
            {
                var Claims = Principal.Claims.ToList();
                ViewBag.FullUserName = Claims.FirstOrDefault(x => x.Type == "FullName").Value;
            }

            bool IsAdministrador = Principal.IsInRole("Administrador");

            if (IsAdministrador)
            {
                ViewBag.FullUserName += "(Administrador)";
            }

            return View();
        }

        public ActionResult AuthenticatedUsers()
        {
            return View();
        }

        [Authorize(Users = "Pedro, Ana")]
        public ActionResult Payments()
        {
            return Content("<h1>Bienvenido usuario autorizado de forma explicita</h1>");
        }

        [Authorize(Roles ="Administrador")]
        public ActionResult AdminUsers()
        {
            return Content("<h1>Bienvenidos Administradores</h1>");
        }

        [Authorize(Roles = "Administrador, Recursos Humanos")]
        public ActionResult AdminRH()
        {
            return Content("<h1>Bienvenidos Administradores y RRHH</h1>");
        }

        [AllowAnonymous]
        public ActionResult GetClaims()
        {
            ClaimsPrincipal Principal = this.User as ClaimsPrincipal;

            var stringBuilder = new System.Text.StringBuilder();

            if(Principal != null)
            {
                foreach (var item in Principal.Claims)
                {
                    stringBuilder.Append($"Tipo de claim: {item.Type}, Valor: {item.Value}<br>");
                }
            }

            return Content(stringBuilder.ToString());
        }

        public ActionResult GetRoles()
        {
            ClaimsPrincipal Principal = this.User as ClaimsPrincipal;

            var stringBuilder = new System.Text.StringBuilder();

            if (Principal != null)
            {
                var roles = Principal.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToList();

                foreach (var item in roles)
                {
                    stringBuilder.Append($"{item}<br>");
                }
            }

            return Content(stringBuilder.ToString());
        }
    }
}