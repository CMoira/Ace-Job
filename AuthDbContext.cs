using AppSec_Assignment_2.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace AppSec_Assignment_2
{
	public class AuthDbContext : IdentityDbContext<ApplicationUser>
	{

		private readonly IConfiguration _configuration;

		public DbSet<PasswordHistory> PasswordHistories { get; set; }

		public AuthDbContext(DbContextOptions<AuthDbContext> options, IConfiguration configuration)
			: base(options)
		{
			_configuration = configuration;
		}

		protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
		{
			if (!optionsBuilder.IsConfigured)
			{
				string connectionString = _configuration.GetConnectionString("AuthConnectionString");
				optionsBuilder.UseSqlServer(connectionString);
			}
		}
	}
}
