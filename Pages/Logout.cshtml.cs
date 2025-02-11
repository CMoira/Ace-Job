using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment_2.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;

namespace AppSec_Assignment_2.Pages
{
    [Authorize]
    public class LogoutModel : PageModel
    {
		private readonly SignInManager<ApplicationUser> signInManager; 
		public LogoutModel(SignInManager<ApplicationUser> signInManager)
		{
			this.signInManager = signInManager;
		}

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostLogoutAsync()
		{
			await signInManager.SignOutAsync(); // Sign out the user

            HttpContext.Response.Cookies.Delete("AuthToken");
            HttpContext.Response.Cookies.Delete("2FAAuthToken");
            HttpContext.Response.Cookies.Delete("2FAToken");
            HttpContext.Response.Cookies.Delete("AppAuthToken");
            HttpContext.Response.Cookies.Delete(".AspNetCore.Session");

            return RedirectToPage("Login");
		}

		public async Task<IActionResult> OnPostDontLogoutAsync()
		{
			return RedirectToPage("Index");
		}


		public void OnGet()
        {
        }
    }
}
