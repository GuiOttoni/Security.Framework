using System;
using Security.Framework.JWT;
using Security.Framework.Enums;
using Security.Framework.Entities;

namespace Security.Framework.Executor
{
    /// <summary>
    /// 
    /// </summary>
    internal class JwtExecutor
    {
        #region .: Class Private Properties :.
        private byte[] _key = { 0x92, 0x1d, 0xf7, 0x14, 0xc0, 0xcb, 0xaf, 0xb9, 0x5b, 0xcf, 0x56, 0x0e, 0xe2, 0x40, 0xa1, 0x15,
                            0xe3, 0x8c, 0x03, 0xb8, 0xa3, 0x2b, 0x0a, 0xb1, 0x49, 0xa9, 0x66, 0x2a, 0x37, 0x85, 0x3c, 0x7e,
                            0xe2, 0xe2, 0xf0, 0x55, 0x9e, 0xce, 0xb4, 0x7b, 0x36, 0xf6, 0x1d, 0x1d, 0x60, 0x07, 0x07, 0x78,
                            0x54, 0x62, 0x48, 0xb5, 0xac, 0x07, 0xd0, 0x5a, 0xec, 0x0f, 0x7d, 0xa7, 0xde, 0x17, 0xed, 0x7d };
        #endregion



        /// <summary>
        /// Function to generate a Json Web Token.
        /// </summary>
        /// <param name="payload">Payload to be encrypted.</param>
        /// <param name="auth">Authenticate class to ensure authentication</param>
        /// <returns>A Json Web Token.</returns>
        protected internal String GenerateToken(Auth auth)
        {
            if(auth.IsAuthenticated)
            {
                String payload = Newtonsoft.Json.JsonConvert.SerializeObject(auth);
                /* Variable Declaration Area */
                String jwt = JWToken.Instance.Encode(payload, _key, JwtAlgorithm.HS256);
                return jwt;
            }
            else
            {
                return "The user was not authenticated.";
            }
        }

        /// <summary>
        /// Method to check if a Json Web Token is Valid.
        /// </summary>
        /// <param name="token">A Json Web Token</param>
        /// <returns>True if token is valid. False otherwise.</returns>
        protected internal Boolean ValidateToken(String token)
        {
            /* Variable Declaration Area */
            Boolean validationResult = JWToken.Instance.ValidateToken(_key, new Jwt(token));

            return validationResult;
        }

        /// <summary>
        /// Method to extract the payload of a Json Web Token.
        /// </summary>
        /// <param name="token">Token to extract the payload.</param>
        /// <returns>The extracted payload.</returns>
        protected internal String ExtractTokenPayload(String token)
        {
            return JWToken.Instance.GetTokenPayload(token);
        }

        /// <summary>
        /// Method to extract the customer ID from a Json Web Token.
        /// </summary>
        /// <param name="token">Token to have customer ID extracted.</param>
        /// <returns>The customer ID Extracted from the payload.</returns>
        protected internal Int32 ExtractCustomerId(String token)
        {
            return 0x01;
        }
    }

}
