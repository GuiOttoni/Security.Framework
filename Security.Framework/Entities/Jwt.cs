using System;
using System.Collections.Generic;
using System.Text;

namespace Security.Framework.Entities
{
    /// <summary>
    /// Internal class used to manipulate a Json Web Token.
    /// </summary>
    public class Jwt
    {
        #region .: Class Public Properties :.
        /// <summary>
        /// Header Segment of the Json Web Token.
        /// </summary>
        public String HeaderSegment { get; set; } = String.Empty;

        /// <summary>
        /// Payload Segment of the Json Web Token.
        /// </summary>
        public String PayloadSegment { get; set; } = String.Empty;

        /// <summary>
        /// Crypto Segment of the Json Web Token.
        /// </summary>
        public Byte[] CryptoSegment { get; set; } = null;

        /// <summary>
        /// Header Segment Data
        /// </summary>
        public Newtonsoft.Json.Linq.JObject HeaderData { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Newtonsoft.Json.Linq.JObject PayloadData { get; set; }
        #endregion

        #region .: Class Constructor :.
        /// <summary>
        /// Class Base Constructor.
        /// </summary>
        /// <param name="token">Token to be decoded.</param>
        public Jwt(String token)
        {
            ParseJwt(token);
        }
        #endregion

        #region .: Class Private Methods :.
        /// <summary>
        ///  Method to parse a Jwt.
        /// </summary>
        /// <param name="token">Token to be decoded.</param>
        private void ParseJwt(String token)
        {
            /* Variable Declaration Area */
            String[] tokenParts = token.Split('.');

            /* If number of segments is different that 3, throw an exception informing the error */
            if (tokenParts.Length != 0x03)
                throw new ApplicationException($"Invalid token. Must contain 3 segments, but it has {tokenParts.Length}");

            this.HeaderSegment = tokenParts[0x00];
            this.PayloadSegment = tokenParts[0x01];
            this.CryptoSegment = Utils.Base64Url.Base64UrlDecode(tokenParts[0x02]);

            DecodeTokenData();
        }

        /// <summary>
        /// Decode Header and Payload Json Objects.
        /// </summary>
        private void DecodeTokenData()
        {
            /* Variable Declaration Area */
            String jsonHeader = Encoding.UTF8.GetString(Utils.Base64Url.Base64UrlDecode(this.HeaderSegment));
            String jsonPayload = Encoding.UTF8.GetString(Utils.Base64Url.Base64UrlDecode(this.PayloadSegment));

            this.HeaderData = Newtonsoft.Json.Linq.JObject.Parse(jsonHeader);
            this.PayloadData = Newtonsoft.Json.Linq.JObject.Parse(jsonPayload);
        }
        #endregion
    }
}
