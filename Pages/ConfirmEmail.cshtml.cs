using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment_2.Model;
using Microsoft.EntityFrameworkCore;

namespace AppSec_Assignment_2.Pages
{
    public class ConfirmEmailModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext _context;
        private readonly IConfiguration _configuration;

        public ConfirmEmailModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext context, IConfiguration configuration)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _context = context;
            _configuration = configuration;
        }

        public async Task<IActionResult> OnGet(string userId, string token)
        {
            if (userId == null || token == null)
            {
                TempData["ErrorMessage"] = "Invalid email confirmation request.";
                return RedirectToPage("Login");
            }

            var user = await signInManager.UserManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToPage("Login");
            }

            // Verify token
            var isValidToken = await signInManager.UserManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, "EmailLogin", token);
            if (!isValidToken)
            {
                return RedirectToPage("Login", new { error = "Invalid or expired confirmation link." });
            }

			// Invalidate all previous sessions by updating security stamp
			await signInManager.UserManager.UpdateSecurityStampAsync(user);

			// Sign in the user
			await signInManager.SignInAsync(user, false);

            // Reset failed attempts after successful login
            await signInManager.UserManager.ResetAccessFailedCountAsync(user);
            ModelState.Clear();

            TempData["SuccessMessage"] = "Your email has been successfully confirmed! Redirecting to login...";


            return RedirectToPage("Index");
        }
    }
}
