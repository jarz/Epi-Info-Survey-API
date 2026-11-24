using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Epi.Web.SurveyAPI.MessageHandlers;
using Epi.Web.SurveyAPI.Web.Common.Security;
using NUnit.Framework;
using System.Web.Http;

namespace Epi.Web.SurveyAPI.Tests.Security
{
    [TestFixture]
    public class SurveyApiAuthenticationTests
    {
        private static readonly string ValidKey = new string('a', 64);

        [Test]
        public void IsValidKey_accepts_64_character_hexadecimal_keys()
        {
            Assert.That(SurveyApiAuthentication.IsValidKey(ValidKey), Is.True);
            Assert.That(SurveyApiAuthentication.IsValidKey(new string('F', 64)), Is.True);
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("not-a-key")]
        [TestCase("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
        [TestCase("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag")]
        public void IsValidKey_rejects_missing_or_malformed_keys(string key)
        {
            Assert.That(SurveyApiAuthentication.IsValidKey(key), Is.False);
        }

        [Test]
        public void IsAuthorized_accepts_a_matching_key_over_https()
        {
            Assert.That(SurveyApiAuthentication.IsAuthorized(ValidKey, ValidKey, true), Is.True);
        }

        [Test]
        public void IsAuthorized_rejects_http_transport()
        {
            Assert.That(SurveyApiAuthentication.IsAuthorized(ValidKey, ValidKey, false), Is.False);
        }

        [Test]
        public void IsAuthorized_rejects_a_mismatched_key()
        {
            Assert.That(SurveyApiAuthentication.IsAuthorized(ValidKey, new string('b', 64), true), Is.False);
        }

        [Test]
        public void IsAuthorized_rejects_a_missing_configured_key()
        {
            Assert.That(SurveyApiAuthentication.IsAuthorized(null, ValidKey, true), Is.False);
        }

        [Test]
        public void IsAuthorized_rejects_a_missing_presented_key()
        {
            Assert.That(SurveyApiAuthentication.IsAuthorized(ValidKey, null, true), Is.False);
        }

        [Test]
        public async Task Handler_rejects_http_requests()
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost/api/surveyResponse"))
            using (var response = await SendAsync(request))
            {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            }
        }

        [Test]
        public async Task Handler_rejects_requests_without_the_api_key()
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/surveyResponse"))
            using (var response = await SendAsync(request))
            {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public async Task Handler_rejects_an_invalid_api_key()
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/surveyResponse"))
            {
                request.Headers.Add(SurveyApiAuthentication.HeaderName, new string('b', 64));
                using (var response = await SendAsync(request))
                {
                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
                }
            }
        }

        [Test]
        public async Task Handler_requires_a_survey_id_after_authenticating_the_client()
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/surveyResponse"))
            {
                request.Headers.Add(SurveyApiAuthentication.HeaderName, ValidKey);
                using (var response = await SendAsync(request))
                {
                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                }
            }
        }

        private static Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            var configuration = new HttpConfiguration();
            request.SetConfiguration(configuration);
            var handler = new APIKeyHandler
            {
                InnerHandler = new UnusedHandler()
            };
            var invoker = new HttpMessageInvoker(handler);
            return SendAndDisposeAsync(invoker, configuration, request);
        }

        private static async Task<HttpResponseMessage> SendAndDisposeAsync(HttpMessageInvoker invoker, HttpConfiguration configuration, HttpRequestMessage request)
        {
            using (invoker)
            using (configuration)
            {
                return await invoker.SendAsync(request, CancellationToken.None);
            }
        }

        private sealed class UnusedHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }
        }
    }
}
