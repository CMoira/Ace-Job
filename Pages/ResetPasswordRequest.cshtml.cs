using AppSec_Assignment_2.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using AppSec_Assignment_2.Services;
using System.ComponentModel.DataAnnotations;

namespace AppSec_Assignment_2.Pages
{
    public class ResetPasswordRequestModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly EmailSender _emailSender;
        private readonly SignInManager<ApplicationUser> signInManager;

        public ResetPasswordRequestModel(UserManager<ApplicationUser> userManager, EmailSender emailSender, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            this.signInManager = signInManager;
        }

        // BindProperty to capture the email address
        [BindProperty]
        // Validate the email address
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public string Email { get; set; }

        [ValidateAntiForgeryToken]
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

                    HttpContext.Session.Clear(); // Clear existing session
                    HttpContext.Session.SetString("ResetToken", token); // Store token in session

                    // Generate AuthToken for session fixation prevention
                    var authToken = Guid.NewGuid().ToString();
                    HttpContext.Session.SetString("AuthToken", authToken);
                    HttpContext.Response.Cookies.Append("AuthToken", authToken, new CookieOptions
                    {
                        HttpOnly = true,  // Prevents access via JavaScript
                        Secure = true,    // Ensures it’s sent over HTTPS
                        SameSite = SameSiteMode.Strict // Prevents CSRF attacks
                    });

                    var resetUrl = Url.Page(
                        "/ResetPassword",
                        pageHandler: null,
                        values: new { email = user.Email },
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
                Console.WriteLine(ex.Message);
                ModelState.AddModelError("", "An error occurred. Please try again.");
                return Page();
			}
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
