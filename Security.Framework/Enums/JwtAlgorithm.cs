using System;
using System.Collections.Generic;
using System.Text;

namespace Security.Framework.Enums
{
    /// <summary>
    /// Enumeration Class to hold Jwt Encryption algorithms.
    /// </summary>
    public enum JwtAlgorithm
    {
        /// <summary>
        /// RSA 256-bit key algorithm.
        /// </summary>
        HS256,

        /// <summary>
        /// HSA 384-bit key algorithm.
        /// </summary>
        HS384,

        /// <summary>
        /// HSA 512-bit key algorithm.
        /// </summary>
        HS512
    }
}
