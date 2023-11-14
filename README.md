<p align="center">
<img src="https://github.com/crowdsecurity/cs-cloudflare-worker-bouncer/raw/main/docs/assets/crowdsec_cloudfare.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

⚠️ This remediation component requires a paid Cloudflare Worker Plan.

# CrowdSec Cloudflare Worker 

A remediation component for Cloudflare.

## How does it work

This remediation component deploys Cloudflare Worker in front of a Cloudflare Zone/Website, which checks if incoming IP addresses are present in a KV store and takes necessary remedial actions. It also periodically updates the KV store with CrowdSec LAPI's decisions.

# Documentation

Please follow the [official documentation](https://docs.crowdsec.net/docs/next/bouncers/cloudflare-workers).
