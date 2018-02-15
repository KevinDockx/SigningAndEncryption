using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Marvin.SigningAndEncryption.Core.Controllers
{
    /// <summary>
    /// Creating valid signed JWT's requires more effort when targeting  
    /// ASP.NET Core - Jose takes care of most of it for in the full .NET framework.  
    /// </summary>
    [Route("api/jwt")]
    public class JwtController : Controller
    {
        // todo (?): implement signing of tokens according to JWT standard
        // https://auth0.com/blog/json-web-token-signing-algorithms-overview/
        //
        // or add sample using MS token middleware
    }
}
