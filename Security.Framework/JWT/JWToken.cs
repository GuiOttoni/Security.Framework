using Microsoft.VisualBasic.CompilerServices;
using System;
using System.Collections.Generic;
using System.Text;
using Security.Framework.Enums;
using Security.Framework.Entities;

namespace Security.Framework.JWT
{
    public sealed class JWToken
    {
        #region .: Internal Class Members :.
        /// <summary>
        /// Internal Lazy Initialization of Class Instance.
        /// </summary>
        private static readonly Lazy<JWToken> lazy = new Lazy<JWToken>(() => new JWToken());

        /// <summary>
        /// Dictionary to hold all hash algorithms.
        /// </summary>
        private Dictionary<JwtAlgorithm, Func<Byte[], Byte[], Byte[]>> _hashAlgorithms;
        #endregion

        #region .: Public Class Properties :.
        /// <summary>
        /// Static Variable to Access Singleton Instance.
        /// </summary>
        public static JWToken Instance { get { return lazy.Value; } }
        #endregion Public Class Properties

        #region .: Class Constructors :.
        /// <summary>
        /// Private Class Constructor to be used when instance is first accessed.
        /// </summary>
        public JWToken()
        {
            /* Including all algorithms in the dictionary. */
            this._hashAlgorithms = new Dictionary<JwtAlgorithm, Func<Byte[], Byte[], Byte[]>>
      {
        { JwtAlgorithm.HS256, ( key, value ) => { using ( var alg = new System.Security.Cryptography.HMACSHA256( key ) ) { return alg.ComputeHash( value ); } } },
        { JwtAlgorithm.HS384, ( key, value ) => { using ( var alg = new System.Security.Cryptography.HMACSHA384( key ) ) { return alg.ComputeHash( value ); } } },
        { JwtAlgorithm.HS512, ( key, value ) => { using ( var alg = new System.Security.Cryptography.HMACSHA512( key ) ) { return alg.ComputeHash( value ); } } }
      };
        }
        #endregion

        #region .: Class Public Method :.

        #region .: Encoding Methods :.
        /// <summary>
        /// Method to generate the JWT.
        /// </summary>
        /// <param name="payload">Data to be encoded.</param>
        /// <param name="key">Hash algorithm key.</param>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <returns>Encoded String.</returns>
        public String Encode(dynamic payload, String key, JwtAlgorithm algorithm)
        {
            return Encode(payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        /// <summary>
        /// Method to generate the JWT.
        /// </summary>
        /// <param name="payload">Data to be encoded.</param>
        /// <param name="key">Hash algorithm key.</param>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <returns>Encoded String.</returns>
        public String Encode(dynamic payload, Byte[] key, JwtAlgorithm algorithm)
        {
            /* Variable Declaration Area */
            IList<String> tokenSegments = new List<String>();
            String dataToSign;
            Byte[] headerData;
            Byte[] payloadData;
            Byte[] bytesToSign;
            Byte[] tokenSignature;
            var tokenHeader = new { algorithm = algorithm.ToString(), type = "JWT" };

            /* Encoding header and payload */
            headerData = Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(tokenHeader, Newtonsoft.Json.Formatting.None));

            if (payload is String)
                payloadData = Encoding.UTF8.GetBytes(payload);
            else
                payloadData = Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(payload, Newtonsoft.Json.Formatting.None));

            /* Including all data in the segment array */
            tokenSegments.Add(Utils.Base64Url.Base64UrlEncode(headerData));
            tokenSegments.Add(Utils.Base64Url.Base64UrlEncode(payloadData));

            /* Create Data String to be signed */
            dataToSign = String.Join(".", tokenSegments);

            /* Convert dataToSign to a byte array */
            bytesToSign = Encoding.UTF8.GetBytes(dataToSign);

            /* Generate Token Signature */
            tokenSignature = this._hashAlgorithms[algorithm](key, bytesToSign);

            /* Include the signature in the token */
            tokenSegments.Add(Utils.Base64Url.Base64UrlEncode(tokenSignature));

            /* Return all the three segments as the new Jwt */
            return String.Join(".", tokenSegments);
        }
        #endregion

        #region .: Decoding Methods :.
        /// <summary>
        /// Method to decode a JWT. 
        /// </summary>
        /// <param name="token">Token to be decoded.</param>
        /// <param name="key">Key to decrypt data.</param>
        /// <returns>The JSON relative to the JWT.</returns>
        public String Decode(String token, String key)
        {
            return Decode(token, key, true);
        }

        /// <summary>
        /// Method to decode a JWT. 
        /// </summary>
        /// <param name="token">Token to be decoded.</param>
        /// <param name="key">Key to decrypt data.</param>
        /// <param name="verify">Verify is the token is vallid.</param>
        /// <returns>The JSON relative to the JWT.</returns>
        public String Decode(String token, String key, Boolean verify)
        {
            /* Variable Declaration Area */
            Jwt jwt = new Jwt(token);

            if (verify == true)
            {
                if (this.ValidateToken(Encoding.UTF8.GetBytes(key), jwt) == false)
                    throw new ApplicationException("Token Signature is Invalid.");
            }

            return jwt.PayloadData.ToString();
        }

        /// <summary>
        /// Extract the current payload of the Json Web Token.
        /// </summary>
        /// <param name="token">A Json Web Token.</param>
        /// <returns>The payload of the Json Web Token.</returns>
        public String GetTokenPayload(String token)
        {
            return new Jwt(token).PayloadData.ToString();
        }
        #endregion

        #endregion

        #region .: Class Private Methods :.
        /// <summary>
        /// Method to validate a jwt token.k
        /// </summary>
        /// <param name="jwt">Token to be validated.</param>
        /// <param name="key">Key to decode the token.</param>
        /// <returns>True if token is valid. False otherwise.</returns>    
        public Boolean ValidateToken(Byte[] keyBytes, Jwt jwt)
        {
            /* Variable Declaration Area */
            Byte[] tokenSignature;
            Byte[] dataToSign = Encoding.UTF8.GetBytes(String.Concat(jwt.HeaderSegment, ".", jwt.PayloadSegment));
            String hashAlgorithm = (String)jwt.HeaderData["algorithm"];
            String decodedCryptogram;
            String decodedSignature;

            tokenSignature = _hashAlgorithms[GetHashAlgorithm(hashAlgorithm)](keyBytes, dataToSign);
            decodedCryptogram = Convert.ToBase64String(jwt.CryptoSegment);
            decodedSignature = Convert.ToBase64String(tokenSignature);

            if (decodedCryptogram != decodedSignature)
                return false;

            return true;
        }
        #endregion

        #region .: Class Private Methods :.
        /// <summary>
        /// Method to select enumeration based on string value.
        /// </summary>
        /// <param name="algorithm">String with Algorithm name.</param>
        /// <returns>Corresponding algorithm enumeration value.</returns>
        private JwtAlgorithm GetHashAlgorithm(String algorithm)
        {
            switch (algorithm)
            {
                case "HS256":
                    return JwtAlgorithm.HS256;

                case "HS384":
                    return JwtAlgorithm.HS384;

                case "HS512":
                    return JwtAlgorithm.HS512;

                default:
                    throw new InvalidOperationException("Algorithm not supported.");
            }
        }
        #endregion
    }
}
