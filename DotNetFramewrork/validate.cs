
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;
namespace validateToken
{
    class Program
    {
        static void  Main(string[] args)
        {
            string token = "eyJ0e.....";
            string myTenant = "72f988bf-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
            var myAudience = "api://xxxxxxxx-xxxx-4607-8ec7-e0a21677e678";
            var myIssuer = "https://sts.windows.net/72f988bf-xxxx-xxxx-xxxx-xxxxxxxxxxxx/";
            var mySecret = "gY42xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));
            var stsDiscoveryEndpoint = String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}/.well-known/openid-configuration", myTenant);
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
            var config =  configManager.GetConfigurationAsync().Result;
            

            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = myAudience,
                ValidIssuer = myIssuer,
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = false,
                IssuerSigningKey = mySecurityKey
                
            };

            var validatedToken = (SecurityToken)new JwtSecurityToken();

            // Throws an Exception as the token is invalid (expired, invalid-formatted, etc.)  
            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            
            Console.WriteLine(validatedToken);
            Console.ReadLine();
        }
    }
}
