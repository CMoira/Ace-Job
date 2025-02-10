using AppSec_Assignment_2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSec_Assignment_2.Model;
using Microsoft.Data.SqlClient;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Net; 
using System.IO;
using System.Text.Json;
using Azure.Core;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using System.Collections.Generic;
using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace AppSec_Assignment_2.Pages
{
	public class LoginModel : PageModel
	{

		[BindProperty]
		public Login LModel { get; set; }

		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly AuthDbContext _context;
		//private readonly IConfiguration _configuration;
		//private readonly HttpClient _httpClient;

		public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext context)
		{
			this.signInManager = signInManager;
			this._userManager = userManager;
			_context = context;
		}

        //// Model for reCAPTCHA response
        //public class ReCaptchaResponse
        //{
        //	public bool Success { get; set; }
        //	public List<string> ErrorMessage { get; set; }
        //}

        //public async Task<bool> VerifyReCaptchaAsync()
        //{
        //	bool result = false;
        //	string captchaResponse = Request.Form["g-recaptcha-response"];
        //	string secretKey = _configuration["GoogleReCaptcha:SecretKey"]; // Get from config

        //	if (string.IsNullOrEmpty(captchaResponse) || string.IsNullOrEmpty(secretKey))
        //	{
        //		return false;
        //	}

        //	string requestUrl = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={captchaResponse}";

        //	HttpWebRequest req = (HttpWebRequest)WebRequest.Create(requestUrl);

        //	try
        //	{
        //		HttpResponseMessage response = await _httpClient.PostAsync(requestUrl, null);
        //		response.EnsureSuccessStatusCode();

        //		string jsonResponse = await response.Content.ReadAsStringAsync();
        //		ReCaptchaResponse data = JsonSerializer.Deserialize<ReCaptchaResponse>(jsonResponse);

        //		return data?.Success ?? false;
        //	}
        //	catch (Exception ex)
        //	{
        //		Console.WriteLine($"reCAPTCHA Verification Failed: {ex.Message}");
        //		return false;
        //	}
        //}

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
				//if (!await VerifyReCaptchaAsync())
				//{
				//	ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
				//	return Page();
				//}
				if (ModelState.IsValid)
				{
                    // Sanitize input
                    LModel.EmailAddress = SanitizeInput(LModel.EmailAddress);
                    LModel.Password = LModel.Password.Trim();

                    var user = await signInManager.UserManager.FindByEmailAsync(LModel.EmailAddress);
					if (user == null)
					{
						ModelState.AddModelError("", "Email or Password is incorrect");
						return Page();
					}

					// Invalidate all previous sessions by updating security stamp
					await signInManager.UserManager.UpdateSecurityStampAsync(user);
					var identityResult = await signInManager.PasswordSignInAsync(LModel.EmailAddress, LModel.Password, LModel.RememberMe, false);
					if (identityResult.Succeeded)
					{
						// Reset failed attempts after successful login
						await signInManager.UserManager.ResetAccessFailedCountAsync(user);
						return RedirectToPage("Index");
					}

					// Add account lockout logic here
					if (identityResult.IsLockedOut)
					{
						ModelState.AddModelError("", "Account is locked out");
						return Page();
					}

					// Increment failed login attempts
					await signInManager.UserManager.AccessFailedAsync(user);

					ModelState.AddModelError("", "Email or Password is incorrect");
				}
				return Page();
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.Message);
				ModelState.AddModelError("", "An error occurred while processing your request. Please Try again");
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
}
