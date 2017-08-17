using Security.Framework.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Security.Framework.Interfaces
{
    /// <summary>
    /// 
    /// </summary>
    public interface IAuthenticator
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        Auth Authenticate();
    }
}
