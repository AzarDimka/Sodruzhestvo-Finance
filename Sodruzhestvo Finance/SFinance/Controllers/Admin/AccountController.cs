using Microsoft.AspNetCore.Mvc;

namespace SFinance.Controllers.Admin
{
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View("~/Views/Admin/Account/Index.cshtml");
        }
    }
}
