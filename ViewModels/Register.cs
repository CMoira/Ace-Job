using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.ComponentModel.DataAnnotations;

namespace AppSec_Assignment_2.ViewModels
{
	public enum GenderType
	{
		Male,
		Female,
		Other
	}
    public class DateOnlyModelBinder : IModelBinder
    {
        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            var value = bindingContext.ValueProvider.GetValue(bindingContext.ModelName).FirstValue;

            if (string.IsNullOrEmpty(value))
            {
                bindingContext.ModelState.AddModelError(bindingContext.ModelName, "Date of Birth is required.");
                return Task.CompletedTask;
            }

            if (DateOnly.TryParse(value, out var dateOnly))
            {
                bindingContext.Result = ModelBindingResult.Success(dateOnly);
            }
            else
            {
                bindingContext.ModelState.AddModelError(bindingContext.ModelName, "Invalid Date format.");
            }

            return Task.CompletedTask;
        }
    }
    public class Register
	{
		[Required]
		[DataType(DataType.Text)]
		[StringLength(50, ErrorMessage = "First Name cannot exceed 50 characters.")]
        [RegularExpression(@"^[a-zA-Z]+([ '-][a-zA-Z]+)*$", ErrorMessage = "Only alphabets, spaces, hyphens, and apostrophes are allowed.")]
        public string FirstName { get; set; }

		[Required]
		[DataType(DataType.Text)]
		[StringLength(50, ErrorMessage = "Last Name cannot exceed 50 characters.")]
        [RegularExpression(@"^[a-zA-Z]+([ '-][a-zA-Z]+)*$", ErrorMessage = "Only alphabets, spaces, hyphens, and apostrophes are allowed.")]
        public string LastName { get; set; }

        // gender should be a dropdown list
        [Required]
        public GenderType Gender { get; set; }

		[Required]
		[DataType(DataType.Text)]
        [RegularExpression(@"(?i)^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC.")]
        public string NRIC { get; set; }

		[Required]
		[DataType(DataType.EmailAddress)]
		//[EmailAddress(ErrorMessage = "Invalid Email Address.")]
		[RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ErrorMessage = "Invalid Email Address.")]

        public string EmailAddress { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$",
		ErrorMessage = "Password must be at least 12 characters long and include at least one lowercase letter, one uppercase letter, one number, and one special character.")]
		public string Password { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
		public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "Date of Birth is required.")]
        //[DataType(DataType.Date)]
        [ModelBinder(BinderType = typeof(DateOnlyModelBinder))]
        [CustomValidation(typeof(Register), "ValidateDateOfBirth")]
        public DateOnly DateOfBirth { get; set; }

        public static ValidationResult ValidateDateOfBirth(DateOnly date, ValidationContext context)
        {
            DateOnly today = DateOnly.FromDateTime(DateTime.Today);
            if (date > today)
                return new ValidationResult("Date of Birth cannot be in the future.");

            if (today.Year - date.Year < 18)
                return new ValidationResult("You must be at least 18 years old to register.");

            if (date < new DateOnly(1900, 1, 1))
                return new ValidationResult("Please enter a valid Date of Birth.");

            return ValidationResult.Success;
        }

        // resume in pdf or docx format
        [Required]
		[DataType(DataType.Upload)]
        [RegularExpression(@"(?i)^.*\.(pdf|docx)$", ErrorMessage = "Resume must be a PDF or DOCX file.")]
        public string Resume { get; set; }

		// whoami
		[DataType(DataType.Text)]
		public string? WhoAmI { get; set; } // Special characters are naturally allowed in strings
	}
}
