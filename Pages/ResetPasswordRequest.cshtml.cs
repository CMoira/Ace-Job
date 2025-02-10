using AppSec_Assignment_2.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using AppSec_Assignment_2.Services;

namespace AppSec_Assignment_2.Pages
{
    public class ResetPasswordRequestModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly EmailSender _emailSender;

        public ResetPasswordRequestModel(UserManager<ApplicationUser> userManager, EmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        // BindProperty to capture the email address
        [BindProperty]
        // Validate the email address
        public string Email { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = await _userManager.FindByEmailAsync(Email);
                    // If the user does not exist, redirect to the confirmation page so that the user cannot enumerate valid email addresses
                    if (user == null)
                    {
                        return RedirectToPage("/ResetPasswordRequestConfirmation");
                    }

                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetUrl = Url.Page(
                        "/ResetPassword",
                        pageHandler: null,
                        values: new { email = user.Email, token },
                        protocol: Request.Scheme);

                    // Send email with SendGrid
                    var subject = "Reset Your Password";
                    var messsage = $"Click <a href='{resetUrl}'>here</a> to reset your password.";

                    await _emailSender.SendEmailAsync(user.Email, subject, messsage);

                    return RedirectToPage("/ResetPasswordRequestConfirmation");
                }
                return Page();
            }
			catch (System.Exception ex)
			{
				ModelState.AddModelError("", ex.Message);
				return Page();
			}
		}


        public void OnGet()
        {
        }
    }
}
