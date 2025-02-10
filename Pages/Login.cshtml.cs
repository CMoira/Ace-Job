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
using System.Text.Json.Serialization;

namespace AppSec_Assignment_2.Pages
{
	public class LoginModel : PageModel
	{

		[BindProperty]
		public Login LModel { get; set; }

		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly AuthDbContext _context;
		private readonly IConfiguration _configuration;
		private readonly HttpClient _httpClient;

		public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, 
			AuthDbContext context, IConfiguration configuration, HttpClient httpClient)
        {
			this.signInManager = signInManager;
			this._userManager = userManager;
			_context = context;
            _configuration = configuration;
            _httpClient = httpClient;
        }
        public async Task<bool> VerifyReCaptchaAsync()
        {
            string captchaResponse = Request.Form["g-recaptcha-response"];
            string secretKey = _configuration["GoogleReCaptcha:SecretKey"]; // Get from config

            if (string.IsNullOrEmpty(captchaResponse) || string.IsNullOrEmpty(secretKey))
            {
                return false;
            }

            string requestUrl = "https://www.google.com/recaptcha/api/siteverify";

            var content = new FormUrlEncodedContent(new[]
            {
				new KeyValuePair<string, string>("secret", secretKey),
				new KeyValuePair<string, string>("response", captchaResponse)
			});

            try
            {
				using (HttpClient httpClient = new HttpClient())
				{
					HttpResponseMessage response = await _httpClient.PostAsync(requestUrl, content);
					response.EnsureSuccessStatusCode();

					string jsonResponse = await response.Content.ReadAsStringAsync();
					Console.WriteLine($"reCAPTCHA Response: {jsonResponse}");  // Debug log

					ReCaptchaResponse data = JsonSerializer.Deserialize<ReCaptchaResponse>(jsonResponse);

					if (data == null || !data.Success)
					{
						Console.WriteLine("reCAPTCHA verification failed.");
						return false;
					}

					// Check score (reCAPTCHA v3)
					if (data.Score < 0.5)
					{
						Console.WriteLine($"Low reCAPTCHA score: {data.Score}. Possible bot.");
						return false;
					}

					return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"reCAPTCHA Verification Failed: {ex.Message}");
                return false;
            }
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
				//int failedAttempts = await signInManager.UserManager.GetAccessFailedCountAsync(user);
				//if (failedAttempts >= 5) // Only enforce reCAPTCHA after 5 failed attempts
				//{ 
				//	if (!await VerifyReCaptchaAsync())
				//	{
				//		ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
				//		return Page();
				//	}
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
					ModelState.Clear();
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
            ViewData["SiteKey"] = _configuration["GoogleReCaptcha:SiteKey"];

            // Check if user is already logged in
            if (signInManager.IsSignedIn(User))
			{
				return RedirectToPage("Index"); // Redirect to homepage or dashboard
			}
			return Page();
		}
	}
}
