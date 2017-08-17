using Security.Framework.Entities;
using Security.Framework.Interfaces;
using System;

namespace Security.Framework.Executor
{
    public abstract class AuthExecutor : IAuthenticator
    {
        private JwtExecutor jwtExecutor = new JwtExecutor();

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public abstract Auth Authenticate();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="auth"></param>
        /// <returns></returns>
        public String GenerateToken(Auth auth)
        {
            return jwtExecutor.GenerateToken(auth);
        }

        public Boolean Validated(String token)
        {
            return jwtExecutor.ValidateToken(token);
        }
    }

}
