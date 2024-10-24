const ipaddr = require('ipaddr.js');
import jwt from '@tsndr/cloudflare-worker-jwt'
import { parse } from "cookie";


const getZoneFromReqURL = (reqURL, actionsByDomain) => {
  // loop through
  for (const [domain] of Object.entries(actionsByDomain)) {
    // if the request URL contains the domain, return the actions
    if (reqURL.includes(domain)) {
      return domain
    }
  }
}

const getSupportedActionForZone = (action, actionsForDomain) => {
  if (actionsForDomain["supported_actions"].includes(action)) {
    return action
  }
  return actionsForDomain["default_action"]
}

const handleTurnstilePost = async (request, body, turnstile_secret, zoneForThisRequest) => {
  const token = body.get('cf-turnstile-response');
  const ip = request.headers.get('CF-Connecting-IP');

  let formData = new FormData();

  formData.append('secret', turnstile_secret);
  formData.append('response', token);
  formData.append('remoteip', ip);

  const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
  const result = await fetch(url, {
    body: formData,
    method: 'POST',
  });

  const outcome = await result.json();

  if (!outcome.success) {
    console.log('Invalid captcha solution');
    return new Response('Invalid captcha solution', {
      status: 401
    });
  } else {
    console.log('Valid captcha solution;', "Issuing JWT token");
    const jwtToken = await jwt.sign({
      data: "captcha solved",
      exp: Math.floor(Date.now() / 1000) + (2 * (60 * 60))
    }, turnstile_secret + ip);
    const newResponse = new Response(null, {
      status: 302
    })
    newResponse.headers.set("Set-Cookie", `${zoneForThisRequest}_captcha=${jwtToken}; Path=/; HttpOnly; Secure; SameSite=Strict;`)
    newResponse.headers.set("Location", request.url)
    return newResponse

  }
}

// request ->
// <-captcha
// solved_captcha ->
// <-server original request with cookie

export default {
  async fetch(request, env, ctx) {

    const doBan = async () => {
      return new Response(await env.CROWDSECCFBOUNCERNS.get("BAN_TEMPLATE"), {
        status: 403,
        headers: { "Content-Type": "text/html" }
      });
    }

    const doCaptcha = async (env, zoneForThisRequest) => {
      // Check if the request has proof of solving captcha
      // If the request has proof of solving captcha, let it pass through
      // If the request does not have proof of solving captcha. Check if the request is submission of captcha.
      // If it's captcha submission, do the validation  and issue a JWT token as a cookie. 
      // Else return the captcha HTML
      const ip = request.headers.get('CF-Connecting-IP');
      let turnstileCfg = await env.CROWDSECCFBOUNCERNS.get("TURNSTILE_CONFIG")
      if (turnstileCfg == null) {
        console.log("No turnstile config found for zone")
        return fetch(request)
      }
      if (typeof turnstileCfg === "string") {
        console.log("Converting turnstile config to JSON")
        turnstileCfg = JSON.parse(turnstileCfg)
        env.CROWDSECCFBOUNCERNS.put("TURNSTILE_CONFIG", turnstileCfg)
      }

      if (!turnstileCfg[zoneForThisRequest]) {
        console.log("No turnstile config found for zone")
        return fetch(request)
      }
      turnstileCfg = turnstileCfg[zoneForThisRequest]

      const cookie = parse(request.headers.get("Cookie") || "");
      if (cookie[`${zoneForThisRequest}_captcha`] !== undefined) {
        console.log("captchaAuth cookie is present")
        // Check if the JWT token is valid
        try {
          const decoded = await jwt.verify(cookie[`${zoneForThisRequest}_captcha`], turnstileCfg["secret"] + ip);
          return fetch(request)
        } catch (err) {
          console.log(err)
        }
        console.log("jwt is invalid")
      }
      if (request.method === "POST") {
        const formBody = await request.clone().formData();
        if (formBody.get('cf-turnstile-response')) {
          console.log("Handling turnstile post")
          return await handleTurnstilePost(request, formBody, turnstileCfg["secret"], zoneForThisRequest)
        }
      }

      const captchaHTML = `
  <!DOCTYPE html>
  <html>
  <head>
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script>
      <title>Captcha</title>
      <style>
          html,
          body {
              height: 100%;
              margin: 0;
          }
  
          .container {
              display: flex;
              align-items: center;
              justify-content: center;
              height: 100%;
          }
  
          .centered-form {
              max-width: 400px;
              padding: 20px;
              background-color: #f0f0f0;
              border-radius: 8px;
          }
      </style>
  </head>
  
  <body>
      <div class="container">
          <form action="?" method="POST" class="centered-form", id="captcha-form">
              <div class="cf-turnstile" data-sitekey="${turnstileCfg["site_key"]}" id="container"></div>
              <br />
          </form>
      </div>
  </body>
  
  <script>
    // if using synchronous loading, will be called once the DOM is ready
    turnstile.ready(function () {
        turnstile.render('#container', {
            sitekey: '${turnstileCfg["site_key"]}',
            callback: function(token) {
              const xhr = new XMLHttpRequest();
              xhr.onreadystatechange = () => {
                if (xhr.readyState === 4) {
                  window.location.reload()
                }
              };
              const form = document.getElementById("captcha-form");
              xhr.open(form.method, "./");
              xhr.send(new FormData(form));
            },
        });
    });
  </script>
  
  </html>
      `
      return new Response(captchaHTML, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
        status: 200
      });
    }

    const getRemediationForRequest = async (request, env) => {
      console.log("Checking for decision against the IP")
      const clientIP = request.headers.get("CF-Connecting-IP");
      let value = await env.CROWDSECCFBOUNCERNS.get(clientIP);
      if (value !== null) {
        return value
      }

      console.log("Checking for decision against the IP ranges")
      let actionByIPRange = await env.CROWDSECCFBOUNCERNS.get("IP_RANGES");
      if (typeof actionByIPRange === "string") {
        actionByIPRange = JSON.parse(actionByIPRange)
      }
      if (actionByIPRange !== null) {
        const clientIPAddr = ipaddr.parse(clientIP);
        for (const [range, action] of Object.entries(actionByIPRange)) {
          if (clientIPAddr.match(ipaddr.parseCIDR(range))) {
            return action
          }
        }
      }
      // Check for decision against the AS
      const clientASN = request.cf.asn.toString();
      value = await env.CROWDSECCFBOUNCERNS.get(clientASN);
      if (value !== null) {
        return value
      }

      // Check for decision against the country of the request
      const clientCountry = request.cf.country.toLowerCase();
      if (clientCountry !== null) {
        value = await env.CROWDSECCFBOUNCERNS.get(clientCountry);
        if (value !== null) {
          return value
        }
      }
      return null
    }

    const incrementMetrics = async (metricName, ipType, origin, remediation_type) => {
      if (env.CROWDSECCFBOUNCERDB !== undefined) {
        let parameters = [metricName, origin || "", remediation_type || "", ipType]
        let query = `
          INSERT INTO metrics (val, metric_name, origin, remediation_type, ip_type)
          VALUES (1, ?, ?, ?, ?)
          ON CONFLICT(metric_name, origin, remediation_type, ip_type) DO UPDATE SET val=val+1
        `;

        await env.CROWDSECCFBOUNCERDB
          .prepare(query)
          .bind(...parameters)
          .run();

      };
    }

    const clientIP = request.headers.get("CF-Connecting-IP");
    const ipType = ipaddr.parse(clientIP).kind();

    await incrementMetrics("processed", ipType)


    let remediation = await getRemediationForRequest(request, env)
    if (remediation === null) {
      console.log("No remediation found for request")
      return fetch(request)
    }
    if (typeof env.ACTIONS_BY_DOMAIN === "string") {
      env.ACTIONS_BY_DOMAIN = JSON.parse(env.ACTIONS_BY_DOMAIN)
    }
    const zoneForThisRequest = getZoneFromReqURL(request.url, env.ACTIONS_BY_DOMAIN);
    console.log("Zone for this request is " + zoneForThisRequest)
    remediation = getSupportedActionForZone(remediation, env.ACTIONS_BY_DOMAIN[zoneForThisRequest])
    console.log("Remediation for request is " + remediation)
    switch (remediation) {
      case "ban":
        await incrementMetrics("dropped", ipType, "crowdsec", "ban")
        return env.LOG_ONLY === "true" ? fetch(request) : await doBan()
      case "captcha":
        await incrementMetrics("dropped", ipType, "crowdsec", "captcha")
        return env.LOG_ONLY === "true" ? fetch(request) : await doCaptcha(env, zoneForThisRequest)
      default:
        return fetch(request)
    }
  }
}