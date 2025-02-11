using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment_2.Model;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

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

        private bool IsValidEmail(string email)
        {
            // Prevent XSS by checking for valid email format
            return new EmailAddressAttribute().IsValid(email) &&
                   Regex.IsMatch(email, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
        }

        public async Task<IActionResult> OnGet(string email)
        {
            try {
                var token = HttpContext.Session.GetString("2FAToken"); // Get token from session

                if (string.IsNullOrEmpty(token)) {
                    TempData["ErrorMessage"] = "Invalid email confirmation request.";
                    return RedirectToPage("Login");
                }

                if (!IsValidEmail(email))
                {
                    ModelState.AddModelError(string.Empty, "Invalid email address.");
                    return Page();
                }

                var sessionToken = HttpContext.Session.GetString("2FAAuthToken");
                var cookieToken = HttpContext.Request.Cookies["2FAAuthToken"];

                if (string.IsNullOrEmpty(sessionToken) || sessionToken != cookieToken)
                {
                    TempData["ErrorMessage"] = "An error occurred while processing your request.";
                    return Page();
                }

                var user = await signInManager.UserManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return RedirectToPage("Login");
                }

                // Invalidate all previous sessions by updating security stamp
                await signInManager.UserManager.UpdateSecurityStampAsync(user);

                HttpContext.Response.Cookies.Delete("2FAAuthToken");
                HttpContext.Response.Cookies.Delete("2FAToken");
                HttpContext.Response.Cookies.Delete(".AspNetCore.Session");

                // Sign in the user
                await signInManager.SignInAsync(user, false);

                // Reset failed attempts after successful login
                await signInManager.UserManager.ResetAccessFailedCountAsync(user);
                ModelState.Clear();

                // Generate session token
                var apptoken = await userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider, "AppToken");
                HttpContext.Session.SetString("AppToken", apptoken); // Store token in session

                // Generate AuthToken for session fixation prevention
                var authToken = Guid.NewGuid().ToString();
                HttpContext.Session.SetString("AppAuthToken", authToken);
                HttpContext.Response.Cookies.Append("AppAuthToken", authToken, new CookieOptions
                {
                    HttpOnly = true,  // Prevents access via JavaScript
                    Secure = true,    // Ensures it’s sent over HTTPS
                    SameSite = SameSiteMode.Strict, // Prevents CSRF attacks
                    Expires = DateTime.UtcNow.AddMinutes(30) // Session expires in 30 minutes
                });


                TempData["SuccessMessage"] = "Your email has been successfully confirmed! Redirecting to login...";
                return RedirectToPage("Index");
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = "An error occurred while confirming your email. Please try again.";
                return Page();
            }
        }
    }
}
