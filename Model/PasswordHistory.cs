using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace AppSec_Assignment_2.Model
{
	public class PasswordHistory
	{
		[Key]
		public int Id { get; set; }

		[Required]
        [ForeignKey("ApplicationUser")]
        public string UserId { get; set; }

        [Required]
		[Column(TypeName = "varchar(MAX)")]
        public string HashedPassword { get; set; }
		public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
	}
}
