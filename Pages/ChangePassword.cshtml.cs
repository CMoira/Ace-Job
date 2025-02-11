using AppSec_Assignment_2.ViewModels;
using AppSec_Assignment_2.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace AppSec_Assignment_2.Pages
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _context;
		private readonly IConfiguration _configuration;

		[BindProperty]
        public ChangePassword CPModel { get; set; }

        [TempData]
        public string SuccessMessage { get; set; }

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, 
            AuthDbContext context, IConfiguration configuration)
		{
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
			_configuration = configuration;
		}

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (ModelState.IsValid)
                {
                    CPModel.CurrentPassword = CPModel.CurrentPassword.Trim();
                    CPModel.NewPassword = CPModel.NewPassword.Trim();
                    CPModel.ConfirmPassword = CPModel.ConfirmPassword.Trim();

                    var user = await _userManager.GetUserAsync(User);
                    if (user == null)
                    {
                        return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
                    }

                    // Step 1: Check if current password is correct first
                    var passwordCheck = await _userManager.CheckPasswordAsync(user, CPModel.CurrentPassword);
                    if (!passwordCheck)
                    {
                        ModelState.AddModelError("", "Incorrect current password.");
                        return Page();
                    }

					// Enforce minimum password age
					var lastPasswordChange = await _context.PasswordHistories
						.Where(up => up.UserId == user.Id)
						.OrderByDescending(up => up.CreatedAt) // Get the most recent password change
						.Select(up => up.CreatedAt)
						.FirstOrDefaultAsync();

                    // Retrieve password policy settings from configuration
					var minPasswordAgeDays = int.Parse(_configuration["PasswordPolicy:MinPasswordAgeDays"]);
					var maxPasswordAgeDays = int.Parse(_configuration["PasswordPolicy:MaxPasswordAgeDays"]);

					if (lastPasswordChange != null) // If user has changed password before
					{
                        var minPasswordAge = (DateTime.UtcNow - lastPasswordChange).TotalDays;
						if (minPasswordAge < minPasswordAgeDays)
						{
							ModelState.AddModelError("", $"You must wait at least {minPasswordAgeDays} days before changing your password again.");
							return Page();
						}
					}

					// Get Last 2 Passwords
					var last2Passwords = await _context.PasswordHistories
                        .Where(up => up.UserId == user.Id)
                        .OrderByDescending(up => up.CreatedAt)
                        .Take(2)
                        .Select(up => up.HashedPassword)
                        .ToListAsync();

					// Check if new password is same as last 2 passwords
					if (last2Passwords.Any(p => _userManager.PasswordHasher.VerifyHashedPassword(user, p, CPModel.NewPassword) == PasswordVerificationResult.Success))
                    {
						ModelState.AddModelError("", "New password cannot be the same as the last 2 passwords.");
                        return Page();
                    }

                    var changePasswordResult = await _userManager.ChangePasswordAsync(user, CPModel.CurrentPassword, CPModel.NewPassword);

                    if (!changePasswordResult.Succeeded)
                    {
                        foreach (var error in changePasswordResult.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                        return Page();
                    }

                    // Add new password to PasswordHistory
                    var passwordHistory = new PasswordHistory
                    {
                        UserId = user.Id,
                        HashedPassword = _userManager.PasswordHasher.HashPassword(user, CPModel.NewPassword),
                        CreatedAt = DateTime.Now
                    };
                    _context.PasswordHistories.Add(passwordHistory);
                    await _context.SaveChangesAsync();

                    // Remove old password from PasswordHistory (Keep the most recent 2)
                    await _context.PasswordHistories
                        .Where(up => up.UserId == user.Id)
                        .OrderByDescending(up => up.CreatedAt)
                        .Skip(2)
                        .ExecuteDeleteAsync();

                    await _signInManager.RefreshSignInAsync(user); 
                    //SuccessMessage = System.Net.WebUtility.HtmlEncode("Your password has been changed.");
                    return RedirectToPage("/Index");
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


        public void OnGet()
        {
        }
    }
}
