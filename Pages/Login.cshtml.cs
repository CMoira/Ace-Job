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
using AppSec_Assignment_2.Services;
using Microsoft.EntityFrameworkCore;
using System.Text.Encodings.Web;

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

        public string SanitizeEmail(string email)
        {
            return Regex.Replace(email, @"[^a-zA-Z0-9@._\-]", ""); // Remove invalid characters
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
					LModel.EmailAddress = SanitizeEmail(LModel.EmailAddress);
					LModel.Password = LModel.Password.Trim();

					var user = await signInManager.UserManager.FindByEmailAsync(LModel.EmailAddress);
					if (user == null)
					{
						ModelState.AddModelError("", "Email or Password is incorrect");
						return Page();
					}

					// Enforce maximum password age
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
						var maxPasswordAge = (DateTime.Now - lastPasswordChange).TotalDays;
						if (maxPasswordAge > maxPasswordAgeDays)
						{
							ModelState.AddModelError("", $"Password has expired. Please reset your password.");
							return RedirectToPage("ResetPasswordRequest");
						}
					}

					//// Invalidate all previous sessions by updating security stamp
					//await signInManager.UserManager.UpdateSecurityStampAsync(user);
					var identityResult = await signInManager.PasswordSignInAsync(LModel.EmailAddress, LModel.Password, LModel.RememberMe, false);
					if (identityResult.Succeeded)
					{


                        //// Invalidate all previous sessions by updating security stamp
                        //await signInManager.UserManager.UpdateSecurityStampAsync(user);

                        //// Sign in the user
                        //await signInManager.SignInAsync(user, false);

                        //// Reset failed attempts after successful login
                        //await signInManager.UserManager.ResetAccessFailedCountAsync(user);
                        //ModelState.Clear();

                        //TempData["SuccessMessage"] = "Your email has been successfully confirmed! Redirecting to login...";
                        //return RedirectToPage("Index");

                        // Email based 2FA
                        var token = await signInManager.UserManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider, "EmailLogin");

                        HttpContext.Session.SetString("2FAToken", token); // Store token in session

                        // Generate AuthToken for session fixation prevention
                        var authToken = Guid.NewGuid().ToString();
                        HttpContext.Session.SetString("2FAAuthToken", authToken);
                        HttpContext.Response.Cookies.Append("2FAAuthToken", authToken, new CookieOptions
                        {
                            HttpOnly = true,  // Prevents access via JavaScript
                            Secure = true,    // Ensures it’s sent over HTTPS
                            SameSite = SameSiteMode.Strict // Prevents CSRF attacks
                        });

                        var confirmationLink = Url.Page(
							"ConfirmEmail", 
							pageHandler: null,
							values: new { email = user.Email },
							protocol: Request.Scheme);

						// Send 2FA token via email
						var emailSender = new EmailSender(_configuration);
						await emailSender.SendEmailAsync(user.Email, "Confirm your login",
							 $"Click <a href='{HtmlEncoder.Default.Encode(confirmationLink)}'>here</a> to complete your login.");

						await signInManager.SignOutAsync();
						TempData["EmailSentMessage"] = "We have sent you an email. Please confirm your login.";

						return RedirectToPage("Login");
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
				ModelState.AddModelError("", "An error occurred. Please try again");
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
