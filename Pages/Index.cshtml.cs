using AppSec_Assignment_2.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AppSec_Assignment_2.Pages
{
	[Authorize]
	public class IndexModel : PageModel
	{
		private readonly ILogger<IndexModel> _logger;
		private UserManager<ApplicationUser> _userManager { get; }

		public ApplicationUser CurrentUser { get; private set; }  // Store user details

		public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager)
		{
			_logger = logger;
			_userManager = userManager;
		}

		public async Task OnGetAsync()
		{
			// Get the logged-in user
			CurrentUser = await _userManager.GetUserAsync(User);

            // Decrypt NRIC before displaying it
			if (CurrentUser != null)
            { 
                CurrentUser.NRIC = EncryptionHelper.DecryptNRIC(CurrentUser.NRIC);
            }
        }
    }
}
