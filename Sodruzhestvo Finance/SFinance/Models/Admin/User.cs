using Microsoft.AspNetCore.Identity;

namespace SFinance.Models.Admin
{
    public class User : IdentityUser
    {
        public string Login { get; set; }

        public string Password { get; set; }

        public User(string login, string password)
        {
            Login = login;
            Password = password;
        }

    }


}
