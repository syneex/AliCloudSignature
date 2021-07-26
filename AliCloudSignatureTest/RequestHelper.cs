using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace AliCloudSignatureTest
{
    public class RequestHelper
    {
        /// <summary>
        /// The type of the return value, supports JSON and XML. The default is XML
        /// </summary>
        public string Format { get; set; } = "JSON";

        /// <summary>
        /// API version number, in date form: YYYY-MM-DD, this version corresponds to 2016-05-11
        /// </summary>
        public string Version { get; } = "2017-05-25";

        /// <summary>
        /// The key ID issued by Alibaba Cloud to the user to access the service
        /// </summary>
        public string AccessKeyId { get; set; } = "ACCESSKEYID";

        /// <summary>
        /// Signature result string
        /// </summary>
        public string Signature { get; set; }

        /// <summary>
        /// Signature method, currently supports HMAC-SHA1
        /// </summary>
        public string SignatureMethod { get; } = "HMAC-SHA1";

        /// <summary>
        /// Request timestamp. The date format is expressed according to the ISO8601 standard, and UTC time is required. The format is YYYY-MM-DDThh:mm:ssZ For example, 2015-01-09T12:00:00Z (it is UTC time January 9, 2015 at 12:0:0)
        /// </summary>
        public string Timestamp { get; set; }

        /// <summary>
        /// Signature algorithm version, the current version is 1.0
        /// </summary>
        public string SignatureVersion { get; } = "1.0";

        /// <summary>
        /// Unique random number, used to prevent network replay attacks. The user must use different random values ​​between different requests
        /// </summary>
        public string SignatureNonce { get; }

        /// <summary>
        /// The HttpMethod.
        /// </summary>
        private readonly HttpMethod _httpMethod;

        /// <summary>
        /// The key issued by Alibaba Cloud to the user to access the service
        /// </summary>
        private string AccessKeySecret { get; set; } = "ACCESSKEYSECRET";

        /// <summary>
        /// The request and url parameters as Dictionary.
        /// </summary>
        private readonly Dictionary<string, string> _parameters;

        /// <summary>
        /// The c'tor of RequestHelper.
        /// </summary>
        /// <param name="httpMethod">The HttpMethod used for the SMS request.</param>
        /// <param name="parameters">The passed parameters.</param>
        public RequestHelper(HttpMethod httpMethod, Dictionary<string, string> parameters)
        {
            SignatureNonce = Guid.NewGuid().ToString();
            Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            _httpMethod = httpMethod;
            _parameters = parameters;
        }

        /// <summary>
        /// Method for adding properties to parameters for signature generation.
        /// </summary>
        private void BuildParameters()
        {
            _parameters.Add(nameof(Format), Format.ToUpper());
            _parameters.Add(nameof(Version), Version);
            _parameters.Add(nameof(AccessKeyId), AccessKeyId);
            _parameters.Add(nameof(SignatureVersion), SignatureVersion);
            _parameters.Add(nameof(SignatureMethod), SignatureMethod);
            _parameters.Add(nameof(SignatureNonce), SignatureNonce);
            _parameters.Add(nameof(Timestamp), Timestamp);
        }

        /// <summary>
        /// Method for generating the URL Signature.
        /// </summary>
        public void ComputeSignature()
        {
            BuildParameters();
            string canonicalizedQueryString2 = string.Join("&",
                _parameters.OrderBy(x => x.Key)
                .Select(x => PercentEncode(x.Key) + "=" + PercentEncode(x.Value)));

            string canonicalizedQueryString = string.Empty;
            string lastParam = string.Empty;
            KeyValuePair<string, string> signName = new KeyValuePair<string, string>(string.Empty, string.Empty);
            foreach (var param in _parameters.OrderBy(x => x.Key))
            {
                if (param.Key != "SignName")
                {
                    if (lastParam == "PhoneNumbers")
                    {
                        lastParam = "anythingelse";
                        canonicalizedQueryString += $"&{PercentEncode("SignName")}={PercentEncode(_parameters["SignName"])}";
                        canonicalizedQueryString += $"&{PercentEncode(param.Key)}={PercentEncode(param.Value)}";
                    }
                    else
                    {
                        canonicalizedQueryString += $"&{PercentEncode(param.Key)}={PercentEncode(param.Value)}";
                    }
                }

                lastParam = param.Key;
            }

            canonicalizedQueryString = canonicalizedQueryString.Remove(0, 1);

            var stringToSign = _httpMethod.ToString().ToUpper() + "&%2F&" + PercentEncode(canonicalizedQueryString);

            var keyBytes = Encoding.UTF8.GetBytes(AccessKeySecret + "&");
            var hmac = new HMACSHA1(keyBytes);
            var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
            Signature = Convert.ToBase64String(hashBytes);
            _parameters.Add(nameof(Signature), Signature);
        }

        /// <summary>
        /// Encode Method.
        /// </summary>
        /// <param name="value">Parameter Value.</param>
        /// <returns>A string.</returns>
        private string PercentEncode(string value)
        {
            return UpperCaseUrlEncode(value)
                .Replace("+", "%20")
                .Replace("*", "%2A")
                .Replace("%7E", "~");
        }

        /// <summary>
        /// Encoding of UpperCase
        /// </summary>
        /// <param name="s">The Parameter Value as a string (in this case from PercentEncode).</param>
        /// <returns>A encoded string.</returns>
        private static string UpperCaseUrlEncode(string s)
        {
            char[] temp = HttpUtility.UrlEncode(s).ToCharArray();
            for (int i = 0; i < temp.Length - 2; i++)
            {
                if (temp[i] == '%')
                {
                    temp[i + 1] = char.ToUpper(temp[i + 1]);
                    temp[i + 2] = char.ToUpper(temp[i + 2]);
                }
            }
            return new string(temp);
        }

        /// <summary>
        /// Generation of final url including all parameters.
        /// </summary>
        /// <param name="url">The base url.</param>
        /// <returns>A string - the final URL.</returns>
        public string GetUrl(string url)
        {
            ComputeSignature();
            return "https://" + url + "/?" +
                string.Join("&", _parameters.Select(x => x.Key + "=" + HttpUtility.UrlEncode(x.Value)));
        }
    }
}
