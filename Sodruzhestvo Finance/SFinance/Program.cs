using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using SFinance.Models.Admin;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SFinance
{

    public class Program
    {

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var userList = new List<User>()
            {
                new User("admin", "www")

            };

            builder.Services.AddAuthorization();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        // указывает, будет ли валидироваться издатель при валидации токена
                        ValidateIssuer = true,
                        // строка, представляющая издателя
                        ValidIssuer = AuthOptions.ISSUER,
                        // будет ли валидироваться потребитель токена
                        ValidateAudience = true,
                        // установка потребителя токена
                        ValidAudience = AuthOptions.AUDIENCE,
                        // будет ли валидироваться время существования
                        ValidateLifetime = true,
                        // установка ключа безопасности
                        IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                        // валидация ключа безопасности
                        ValidateIssuerSigningKey = true,
                    };
                });
            var app = builder.Build();

            app.UseAuthentication();
            app.UseAuthorization();

            app.Map("/login", (User loginData) =>
            {
                // находим пользователя 
                User? user = userList.FirstOrDefault(p => p.Email == loginData.Login && p.Password == loginData.Password);
                var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Login) };
                // создаем JWT-токен
                var jwt = new JwtSecurityToken(
                issuer: AuthOptions.ISSUER,
                audience: AuthOptions.AUDIENCE,
                        claims: claims,
                        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));

                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                // формируем ответ
                var response = new
                {
                    access_token = encodedJwt,
                    username = user.Email
                };

                return Results.Json(response);
            });

            app.Map("/data", [Authorize] () => new { message = "Hello World!" });

            app.Run();

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }

        public class AuthOptions
        {
            public const string ISSUER = "MyAuthServer"; // издатель токена
            public const string AUDIENCE = "MyAuthClient"; // потребитель токена
            const string KEY = "mysupersecret_secretsecretsecretkey!123";   // ключ для шифрации
            public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
        }

        record class Person(string Email, string Password);
    }
}
