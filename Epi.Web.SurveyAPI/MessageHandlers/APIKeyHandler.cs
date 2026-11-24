using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Epi.Web.SurveyAPI.Repository;
using System.Configuration;
using System.Web.Http;
using Epi.Web.SurveyAPI.Web.Common.Security;

namespace Epi.Web.SurveyAPI.MessageHandlers
{
    public class APIKeyHandler : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri == null ||
                !string.Equals(request.RequestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return request.CreateResponse(HttpStatusCode.BadRequest, "HTTPS is required.");
            }

            string presentedKey;
            if (!TryGetSingleHeader(request, SurveyApiAuthentication.HeaderName, out presentedKey) ||
                !SurveyApiAuthentication.IsAuthorized(
                    ConfigurationManager.AppSettings[SurveyApiAuthentication.SharedKeySetting],
                    presentedKey,
                    true))
            {
                return request.CreateResponse(HttpStatusCode.Unauthorized, "Authentication failed.");
            }

            string surveyIdHeader;
            Guid surveyId;
            if (!TryGetSingleHeader(request, "SurveyId", out surveyIdHeader) ||
                !Guid.TryParse(surveyIdHeader, out surveyId))
            {
                return request.CreateResponse(HttpStatusCode.BadRequest, "A valid SurveyId header is required.");
            }

            var requestScopedService = request.GetDependencyScope()
                .GetService(typeof(ISurveyResponseRepository)) as ISurveyResponseRepository;
            if (requestScopedService == null)
            {                
                throw new InvalidOperationException("The survey response repository is not registered.");
            }

            requestScopedService.SurveyId = surveyId;
            var surveyInfo = requestScopedService.GetSurveyInfoById(surveyIdHeader);
            if (surveyInfo == null)
            {
                return request.CreateResponse(HttpStatusCode.Unauthorized, "Authentication failed.");
            }

            requestScopedService.PublisherKey = surveyInfo.UserPublishKey;
            requestScopedService.OrgKey = surveyInfo.OrganizationKey;
            return await base.SendAsync(request, cancellationToken);
        }

        private static bool TryGetSingleHeader(HttpRequestMessage request, string headerName, out string value)
        {
            value = null;
            IEnumerable<string> values;
            if (!request.Headers.TryGetValues(headerName, out values))
            {
                return false;
            }

            string[] headerValues = values.ToArray();
            if (headerValues.Length != 1)
            {
                return false;
            }

            value = headerValues[0];
            return true;
        }
    }
}