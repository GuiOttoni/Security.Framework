using System;
using System.Collections.Generic;
using System.Text;

namespace Security.Framework.Entities
{
    /// <summary>
    /// Class that will hold information regarding the user validation
    /// </summary>
    public class Auth
    {
        /// <summary>
        /// Username of your user
        /// </summary>

        public String Username { get; set; }

        /// <summary>
        /// The ID
        /// </summary>
        public String CustomerId { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Boolean IsAuthenticated { get; set; }


    }
}
