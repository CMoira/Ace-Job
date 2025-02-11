using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment_2.Model;

namespace AppSec_Assignment_2.Pages

{
    public class ResetPasswordConfirmationModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;

        public ResetPasswordConfirmationModel(SignInManager<ApplicationUser> signInManager)
        {
            this.signInManager = signInManager;
        }

        public IActionResult OnGet()
        {
            // Check if user is already logged in
            if (signInManager.IsSignedIn(User))
            {
                // Redirect to home page if user is already logged in
                return RedirectToPage("Index");
            }
            return Page();
        }
    }
}
