using AppSec_Assignment_2;
using AppSec_Assignment_2.Model;
using AppSec_Assignment_2.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
//builder.Services.AddDbContext<AuthDbContext>();
builder.Services.AddDbContext<AuthDbContext>(options =>
	options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
	.AddEntityFrameworkStores<AuthDbContext>()
	.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(Config =>
{
	Config.LoginPath = "/Login";
	Config.LogoutPath = "/Logout";
	Config.AccessDeniedPath = "/Error/AccessDenied";
	Config.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict; // Prevents CSRF attacks
	Config.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always; // Ensures the cookie is sent only over HTTPS
	Config.Cookie.HttpOnly = true; // Prevents client side JS from accessing the cookie
	Config.ExpireTimeSpan = TimeSpan.FromMinutes(15); // Sets the expiration time for the cookie
	Config.SlidingExpiration = true; // Automatically refreshes the expiration time if the user is active
});

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
	options.ValidationInterval = TimeSpan.FromSeconds(10); // Sets the time interval for checking the security stamp
});

builder.Services.Configure<IdentityOptions>(options =>
{
	options.Password.RequiredLength = 12;
	options.Password.RequireDigit = true;
	options.Password.RequireLowercase = true;
	options.Password.RequireUppercase = true;
	options.Password.RequireNonAlphanumeric = true;

	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
	options.Lockout.MaxFailedAccessAttempts = 3;
	options.Lockout.AllowedForNewUsers = true;
});

builder.Services.AddTransient<EmailSender>();

// Service for the reset password token
builder.Services.AddSession(options => 
{
    options.IdleTimeout = TimeSpan.FromMinutes(15); // Expire session after 15 min
    options.Cookie.HttpOnly = true; // Prevent JavaScript access
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Use HTTPS
    options.Cookie.SameSite = SameSiteMode.Strict; // Prevent CSRF attacks
});


builder.Services.AddHttpClient();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Error");
	// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
	app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseStatusCodePagesWithRedirects("/Error/{0}");
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapRazorPages();

app.Run();
