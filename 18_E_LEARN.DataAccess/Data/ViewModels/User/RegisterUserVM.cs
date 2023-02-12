using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _18_E_LEARN.DataAccess.Data.ViewModels.User
{
    public class RegisterUserVM
    {
        //public string Username { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Surname { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
        //public bool EmailConfirmed { get; set; }
        public string PhoneNumber { get; set; } = string.Empty;
        //public bool PhoneNumberConfirmed { get; set; }
        public string Role { get; set; } = string.Empty; 
        
    }
}
