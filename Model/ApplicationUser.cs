using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;

namespace AppSec_Assignment_2.Model
{
	public class ApplicationUser : IdentityUser
	{
		[Required]
		[StringLength(100)]
		public string Name { get; set; }

		[Required]
		public string NRIC { get; set; }

		[Required]
		[StringLength(10)]
		public string Gender { get; set; }

		[Required]
		public DateOnly DateOfBirth { get; set; }

		[Required]
		[StringLength(255)]
		public string Resume { get; set; }

		public string? WhoAmI { get; set; }

	}
}
