using System;
using System.Collections.Generic;
using System.Text;

namespace Security.Framework.Utils
{
    /// <summary>
    /// Static Class to Encode and Decode Base64 Urls.
    /// </summary>
    public static class Base64Url
    {
        #region .: Base URL 64 Utilities :.
        /// <summary>
        /// Create an encoding based on the Jwt Specification.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static String Base64UrlEncode(byte[] data)
        {
            /* Variable Declaration Area */
            String answer = Convert.ToBase64String(data);

            /* Remove any trailing '='s */
            answer = answer.Split('=')[0x00];

            /* 62nd Char of Encoding */
            answer = answer.Replace('+', '-');

            /* 63rd Char of Encoding */
            answer = answer.Replace('/', '_');

            return answer;
        }

        /// <summary>
        /// Decode data, according to the Jwt Specification.
        /// </summary>
        /// <param name="data">Data to be decoded.</param>
        /// <returns>A byte array with data decodd.</returns>
        public static byte[] Base64UrlDecode(String data)
        {
            /* Variable Declaration Area */
            String answer = data;

            /* 62nd Char of Encoding */
            answer = answer.Replace('-', '+');

            /* 63rd Char of Encoding */
            answer = answer.Replace('_', '/');

            /* Padding with trailing '='s */
            switch (answer.Length % 0x04)
            {
                /* No padding chars needed */
                case 0:
                    break;

                /* Including 2 padding chars */
                case 2:
                    answer += "==";
                    break;

                /* Including 1 padding char */
                case 3:
                    answer += "=";
                    break;

                default:
                    throw new System.Exception("The base64URL informed is invalid.");
            }

            /* .Net Standard Decoder */
            return Convert.FromBase64String(answer);
        }
        #endregion
    }
}
