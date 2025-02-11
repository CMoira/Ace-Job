using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text;
using System.Data;
using System.Data.SqlClient;
using AppSec_Assignment_2.Model;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Web;

namespace AppSec_Assignment_2.Pages
{

    public class RegisterModel : PageModel
    {

		private UserManager<ApplicationUser> userManager { get; }
		private SignInManager<ApplicationUser> signInManager { get; }
        private readonly AuthDbContext _context;

        [BindProperty]
		public Register RModel { get; set; }

		public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, AuthDbContext context)
        {
            _context = context;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        // Sanitize user input
        public static string SanitizeInput(string input)
        {
            return HttpUtility.HtmlEncode(input);
        }

        [ValidateAntiForgeryToken]
		public async Task<IActionResult> OnPostAsync()
		{
			try
			{
				if (ModelState.IsValid) // check if the model state is valid
				{

					// Check if email exists in the database
					var userExists = await userManager.FindByEmailAsync(RModel.EmailAddress);
					if (userExists != null)
					{
						ModelState.AddModelError("", "Email already exists.");
						return Page();
					}

					// Encrypt NRIC before storing it
					string encryptedNRIC = EncryptionHelper.EncryptNRIC(SanitizeInput(RModel.NRIC).Trim());

					var user = new ApplicationUser
					{
						UserName = SanitizeInput(RModel.EmailAddress).Trim(),
						Name = SanitizeInput(RModel.FirstName).Trim() + " " + SanitizeInput(RModel.LastName).Trim(),
                        Email = SanitizeInput(RModel.EmailAddress).Trim(),
						NRIC = encryptedNRIC,
						Gender = SanitizeInput(RModel.Gender.ToString().Trim()),
						DateOfBirth = RModel.DateOfBirth,
						Resume = SanitizeInput(RModel.Resume).Trim(),
                        WhoAmI = SanitizeInput(RModel.WhoAmI),
                        PhoneNumber = null // Explicitly set to null
                    };
					var result = await userManager.CreateAsync(user, RModel.Password);
					if (result.Succeeded)
					{
                        // Store password history
                        var passwordHistory = new PasswordHistory
                        {
                            UserId = user.Id,
                            HashedPassword = userManager.PasswordHasher.HashPassword(user, RModel.Password),
                            CreatedAt = DateTime.Now
                        };

                        await _context.PasswordHistories.AddAsync(passwordHistory);
                        await _context.SaveChangesAsync();

                        await signInManager.SignInAsync(user, isPersistent: false);
						return RedirectToPage("/Index");
					}
					foreach (var error in result.Errors)
					{
						ModelState.AddModelError("", error.Description);
					}
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

		public IActionResult OnGet()
		{
			// Check if user is already logged in
			if (signInManager.IsSignedIn(User))
			{
				return RedirectToPage("Index"); // Redirect to homepage or dashboard
			}
			return Page();
		}
	}

	public static class EncryptionHelper
	{
		private static readonly byte[] Key;
		private static readonly byte[] IV;

		static EncryptionHelper()
		{
			var config = new ConfigurationBuilder()
				.SetBasePath(AppContext.BaseDirectory)
				.AddJsonFile("appsettings.json")
				.AddJsonFile("appsettings.Development.json", optional: true)
				.Build();

			// Convert Base64-encoded key and IV from appsettings.json into byte arrays
			Key = Convert.FromBase64String(config["EncryptionSettings:AESKey"]);
			IV = Convert.FromBase64String(config["EncryptionSettings:AESIV"]);
		}

		// Encrypt NRIC using AES
		public static string EncryptNRIC(string plainText)
		{
			using (Aes aes = Aes.Create())
			{
				aes.Key = Key;
				aes.IV = IV;
				ICryptoTransform encryptor = aes.CreateEncryptor();

				byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
				byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);

				return Convert.ToBase64String(encryptedBytes);
			}
		}

		// Decrypt NRIC using AES
		public static string DecryptNRIC(string encryptedText)
		{
			using (Aes aes = Aes.Create())
			{
				aes.Key = Key;
				aes.IV = IV;
				ICryptoTransform decryptor = aes.CreateDecryptor();

				byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
				byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

				return Encoding.UTF8.GetString(decryptedBytes);
			}
		}
	}
}
