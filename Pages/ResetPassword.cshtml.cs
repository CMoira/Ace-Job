using AppSec_Assignment_2.Model;
using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AppSec_Assignment_2.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager)
        {
            this.userManager = userManager;
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

                    var result = await userManager.ResetPasswordAsync(user, RPModel.Token, RPModel.NewPassword);
                    if (result.Succeeded)
                    {
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
				ModelState.AddModelError("", ex.Message);
				return Page();
			}
		}
    }
}
