using System;
using System.Collections.Generic;
using System.Net.Http;

namespace AliCloudSignatureTest
{
    public class Program
    {
        static void Main(string[] args)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            parameters.Add("PhoneNumbers", "PHONENUMBER");
            parameters.Add("SignName", "SIGNATURE");
            parameters.Add("TemplateCode", "TEMPLATENAME");
            parameters.Add("TemplateParam", "{\"TEMPLATE PARAMETER\": \"TEMPLATE VALUE\"}");
            parameters.Add("Action", "SendSms");
            RequestHelper helper = new RequestHelper(HttpMethod.Get, parameters);

            HttpClient client = new HttpClient();
            var uri = helper.GetUrl("dysmsapi.aliyuncs.com");
            Console.WriteLine(uri);
            HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, uri);
            var response = client.SendAsync(req).Result;

            Console.WriteLine(response.Content.ReadAsStringAsync().Result);
            Console.ReadKey();
        }
    }
}