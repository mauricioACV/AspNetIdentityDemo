using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace Web_MVC.Models
{
    public class LoginViewModel
    {
        [Display(Name ="Correo:")]
        public string Email { get; set; }

        [Display(Name = "Clave de Acceso:")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Recordarme")]
        public bool RememberMe { get; set; }
    }
}