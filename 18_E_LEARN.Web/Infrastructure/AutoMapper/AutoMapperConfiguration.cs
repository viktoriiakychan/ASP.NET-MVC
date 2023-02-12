using _18_E_LEARN.DataAccess.AutoMapper.User;

namespace _18_E_LEARN.Web.Infrastructure.AutoMapper
{
    public class AutoMapperConfiguration
    {
        public static void Config(IServiceCollection services)
        {
            services.AddAutoMapper(typeof(AutoMapperUserProfile));
        }
    }
}
