using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web.Resource;

namespace WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class SecretController : ControllerBase
    {
        private readonly SecretClient _secretClient;
        private readonly ILogger _logger;

        public SecretController(SecretClient secretClient, ILogger<SecretController> logger)
        {
            _secretClient = secretClient ?? throw new ArgumentNullException(nameof(secretClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // This action will only accept tokens 1) for users, and 2) having the "access_as_user" scope for this API
        [HttpGet("my")]
        [RequiredScope(Scopes.AccessAsUser)]
        public async Task<ActionResult<IEnumerable<SecretProperties>>> GetByUser(CancellationToken cancellationToken)
        {
            string userName = GetUserName();
            _logger.LogDebug("Looking up secrets for {user}", userName);
            var secretList = new List<SecretProperties>();
            int i = 0;
            await foreach (var secret in _secretClient.GetPropertiesOfSecretsAsync(cancellationToken))
            {
                if (secret.Name.StartsWith(userName))
                {
                    secretList.Add(secret);
                    i++;
                }
            }
            _logger.LogDebug("Found {count} secrets for {user}", i, userName);
            return secretList;
        }

        [HttpGet("ping")]
        [AllowAnonymous]
        public ActionResult<string> Ping()
        {
            _logger.LogDebug("Application is up at {timestamp:u}", DateTimeOffset.UtcNow);
            return Ok("UP");
        }

        private string GetUserName()
        {
            string name = User.FindFirst("preferred_username")?.Value;
            if (name is null)
            {
                throw new InvalidOperationException("No \"preferred_username\" claim found.");
            }

            int index = name.IndexOf("@");
            if (index < 1)
            {
                return name;
            }
            return name.Substring(0, index);
        }
    }
}
