using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Resource;

namespace BackendForFrontend
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class HelloController : ControllerBase
    {
        private readonly ILogger _logger;

        public HelloController(ILogger<HelloController> logger)
        {
            _logger = logger;
        }

        // The Web API will only accept tokens 1) for users, and 2) having the "access_as_user" scope for this API
        [HttpGet]
        [RequiredScope(Scopes.AccessAsUser)]
        public ActionResult<object> Get()
        {
            var nameClaim = User.FindFirst(ClaimConstants.Name);
            var issuedByClaim = User.FindFirst("iss");
            var issuedForClaim = User.FindFirst("aud");
            // TODO: This _should_ surface as ClaimConstants.Scp, but actually is exposed as ClaimConstants.Scope
            var scopeClaim = User.FindFirst(ClaimConstants.Scope);

            _logger.LogDebug(
                "name: '{name}', iss: '{iss}', aud: '{aud}', scp: '{scp}'",
                nameClaim,
                issuedByClaim,
                issuedForClaim,
                scopeClaim);

            var content =
                new
                {
                    Name = nameClaim?.Value,
                    Iss = issuedByClaim?.Value,
                    Aud = issuedForClaim?.Value,
                    Scp = scopeClaim?.Value
                };

            return Ok(content);
        }
    }
}
