using AppSec_Assignment_2.Model;
using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace AppSec_Assignment_2.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
		private readonly AuthDbContext _context;

		public ResetPasswordModel(UserManager<ApplicationUser> userManager, AuthDbContext context)
		{
            this.userManager = userManager;
			_context = context;
		}

        [BindProperty]
        public ResetPassword RPModel { get; set; }

        public void OnGet(string token, string email)
        {
            RPModel = new ResetPassword
            {
                Token = token,
                Email = email
            };
        }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (ModelState.IsValid)
                {
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
