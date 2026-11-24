using System;

namespace Epi.Web.SurveyAPI.Web.Common.Security
{
    public static class SurveyApiAuthentication
    {
        public const string SharedKeySetting = "SurveyApiSharedKey";
        public const string HeaderName = "X-Epi-Info-API-Key";
        private const int SharedKeyLength = 64;

        public static bool IsValidKey(string key)
        {
            if (key == null || key.Length != SharedKeyLength)
            {
                return false;
            }

            for (int i = 0; i < key.Length; i++)
            {
                char value = key[i];
                if (!((value >= '0' && value <= '9') ||
                      (value >= 'a' && value <= 'f') ||
                      (value >= 'A' && value <= 'F')))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsAuthorized(string configuredKey, string presentedKey, bool secureTransport)
        {
            if (!secureTransport || !IsValidKey(configuredKey) || !IsValidKey(presentedKey))
            {
                return false;
            }

            int difference = 0;
            for (int i = 0; i < SharedKeyLength; i++)
            {
                difference |= configuredKey[i] ^ presentedKey[i];
            }

            return difference == 0;
        }
    }
}
