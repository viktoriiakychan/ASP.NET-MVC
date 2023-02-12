using _18_E_LEARN.BusinessLogic.Services;
using _18_E_LEARN.DataAccess.Data.Context;
using _18_E_LEARN.DataAccess.Data.Models.User;
using _18_E_LEARN.DataAccess.Data.ViewModels.User;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;

namespace _18_E_LEARN.Web.Infrastructure.Services
{
    public class ServicesConfiguration
    {
        public static void Config(IServiceCollection services)
        {
            services.AddControllersWithViews();

            // Add razor pages
            services.AddRazorPages(); // razor pages is 

            // Add application database context
            services.AddDbContext<AppDbContext>();

            //Add UserService
            services.AddTransient<UserService>();

            //Add EmailService
            services.AddTransient<EmailService>();

            // Add Identity
            services.AddIdentity<AppUser, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedEmail = true;
                options.User.RequireUniqueEmail = true; // no similar emails!
                options.Lockout.MaxFailedAccessAttempts = 5; // if a user logs out for 5 times but it is wrong, we block him/her
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Password.RequiredLength = 6;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true; // ! ? 

            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            services.AddFluentValidation(options =>
            {
                options.DisableDataAnnotationsValidation = true;
                options.ImplicitlyValidateChildProperties = true;
                options.RegisterValidatorsFromAssemblyContaining<LoginUserVM>();
            });
        }
    }
}
