using AppSec_Assignment_2.Model;
using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using System.Web;

namespace AppSec_Assignment_2.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
		private readonly AuthDbContext _context;
        private readonly SignInManager<ApplicationUser> signInManager;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, AuthDbContext context,
            SignInManager<ApplicationUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _context = context;
		}

        [BindProperty]
        public ResetPassword RPModel { get; set; }

        private bool IsValidEmail(string email)
        {
            // Prevent XSS by checking for valid email format
            return new EmailAddressAttribute().IsValid(email) &&
                   Regex.IsMatch(email, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
        }

        public static string SanitizeInput(string input)
        {
            return HttpUtility.HtmlEncode(input);
        }

        public IActionResult OnGet(string email)
        {
            // Check if user is already logged in
            if (signInManager.IsSignedIn(User))
            {
                return RedirectToPage("Index"); // Redirect to homepage or dashboard
            }
            
            var token = HttpContext.Session.GetString("ResetToken"); // Get token from session

            if (string.IsNullOrEmpty(token))
            {
                ModelState.AddModelError("", "Invalid or expired token.");
                return Page();
            }

            if (!IsValidEmail(email))
            {
                ModelState.AddModelError(string.Empty, "Invalid email address.");
                return Page();
            }

            RPModel = new ResetPassword
            {
                Token = token,
                Email = email
            };
            return Page();
        }

		[ValidateAntiForgeryToken]
		public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                var sessionToken = HttpContext.Session.GetString("AuthToken");
                var cookieToken = HttpContext.Request.Cookies["AuthToken"];

                if (string.IsNullOrEmpty(sessionToken) || sessionToken != cookieToken)
                {
                    // redirect to unauthorized page
                    ModelState.AddModelError("", "An error occurred while processing your request.");
                    return Page();
                }
                if (ModelState.IsValid)
                {
                    RPModel.NewPassword = SanitizeInput(RPModel.NewPassword);


                    var user = await userManager.FindByEmailAsync(RPModel.Email);
                    if (user == null)
                    {
                        return RedirectToPage("/ResetPasswordConfirmation");
                    }

					// Get Last 2 Passwords
					var last2Passwords = await _context.PasswordHistories
						.Where(up => up.UserId == user.Id)
						.OrderByDescending(up => up.CreatedAt)
						.Take(2)
						.Select(up => up.HashedPassword)
						.ToListAsync();

					// Check if new password is same as last 2 passwords
					if (last2Passwords.Any(p => userManager.PasswordHasher.VerifyHashedPassword(user, p, RPModel.NewPassword) == PasswordVerificationResult.Success))
					{
						ModelState.AddModelError("", "New password cannot be the same as the last 2 passwords.");
						return Page();
					}

					var result = await userManager.ResetPasswordAsync(user, RPModel.Token, RPModel.NewPassword);
                    if (result.Succeeded)
                    {
						// Add new password to PasswordHistory
						PasswordHistory ph = new PasswordHistory
						{
							UserId = user.Id,
							HashedPassword = userManager.PasswordHasher.HashPassword(user, RPModel.NewPassword),
							CreatedAt = DateTime.Now
						};
						_context.PasswordHistories.Add(ph);
						await _context.SaveChangesAsync();

						// Remove old password from PasswordHistory (Keep the most recent 2)
						await _context.PasswordHistories
						    .Where(up => up.UserId == user.Id)
						    .OrderByDescending(up => up.CreatedAt)
						    .Skip(2)
						    .ExecuteDeleteAsync();

                        //HttpContext.Session.Remove("ResetToken"); // Clear token after use
                        HttpContext.Response.Cookies.Delete("AuthToken"); // Removes AuthToken cookie
                        HttpContext.Response.Cookies.Delete(".AspNetCore.Session"); // Expire session cookie
                        await signInManager.SignOutAsync(); // Log out if authenticated
                        return RedirectToPage("/ResetPasswordConfirmation");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return Page();
                }
                return Page();
            }
			catch (Exception ex)
			{
                Console.WriteLine(ex.Message);
                ModelState.AddModelError("", "An error occurred. Please try again.");
                return Page();
			}
		}
    }
}
