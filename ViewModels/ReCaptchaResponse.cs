using System.Text.Json.Serialization;

namespace AppSec_Assignment_2.ViewModels
{
	// Model for reCAPTCHA response
	public class ReCaptchaResponse
	{
		[JsonPropertyName("success")]
		public bool Success { get; set; }

		[JsonPropertyName("score")]
		public float Score { get; set; }

		[JsonPropertyName("error-codes")]
		public List<string> ErrorMessage { get; set; }
	}
}
