using System.ComponentModel.DataAnnotations;

namespace AppSec_Assignment_2.ViewModels
{
	public class ChangePassword
	{
		[Required]
		[DataType(DataType.Password)]
		[Display(Name = "Current Password")]
		public string CurrentPassword { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{12,}$",
		ErrorMessage = "Password must be at least 12 characters long and include at least one lowercase letter, one uppercase letter, one number, and one special character.")]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[Compare(nameof(NewPassword), ErrorMessage = "Password and confirmation password does not match.")]
		[Display(Name = "Confirm Password")]
		public string ConfirmPassword { get; set; }
	}
}
