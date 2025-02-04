using Microsoft.AspNetCore.Identity;

namespace AspMvcAuth.Models
{
    public class ApplicationUser : IdentityUser<int>
    {
        /// <summary>
        /// День рождения
        /// </summary>
        public DateOnly Birthday { get; set; }

        /// <summary>
        /// Организация
        /// </summary>
        public string Organization { get; set; }

        /// <summary>
        /// Департамент
        /// </summary>
        public string Department { get; set; }
    }
}
