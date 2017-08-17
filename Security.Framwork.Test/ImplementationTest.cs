using Security.Framework.Executor;
using System;
using System.Collections.Generic;
using System.Text;
using Security.Framework.Entities;

namespace Security.Framwork.Test
{
    public class ImplementationTest
    {
        public void DoIt()
        {
            Authenticator authenticator = new Authenticator();
            Auth auth = new Auth();
            auth = authenticator.Authenticate();
            String token = authenticator.GenerateToken(auth);
            authenticator.Validated(token);
        } 
    }

    public class Authenticator : AuthExecutor
    {
        public override Auth Authenticate()
        {
            throw new NotImplementedException();
        }


    }
}
