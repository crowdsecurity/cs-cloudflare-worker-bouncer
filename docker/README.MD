# cloudflare-bouncer

A bouncer that syncs the decisions made by CrowdSec with CloudFlare's firewall. Manages multi user, multi account, multi zone setup. Supports IP, Country and AS scoped decisions.

### Initial Setup

```bash
docker run crowdsecurity/cloudflare-worker-bouncer \
 -g <CLOUDFLARE_TOKEN1> <CLOUDFLARE_TOKEN2> > cfg.yaml # auto-generate cloudflare config for provided space separated tokens 
vi cfg.yaml # review config and set `crowdsec_lapi_key`
```

The `crowdsec_lapi_key` can be obtained by running the following:
```bash
sudo cscli -oraw bouncers add cloudflarebouncer # -oraw flag can discarded for human friendly output.
```

The `crowdsec_lapi_url` must be accessible from the container.

### Run the bouncer

```bash
  docker run \
  -v $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-worker-bouncer.yaml \
  -p 2112:2112 \
  crowdsecurity/cloudflare-worker-bouncer
```


# Configuration

Configuration file must be at `/etc/crowdsec/bouncers/crowdsec-cloudflare-worker-bouncer.yaml`

```yaml
# CrowdSec Config
crowdsec_config:
  lapi_url: http://localhost:8080/
  lapi_key: ${API_KEY}
  update_frequency: 10s

#Cloudflare Config. 
cloudflare_config:
cloudflare_config:
    accounts:
        - id: 
          ban_template: "" # template to use for ban action, set empty to use default
          zones:
            - zone_id:  # example.com
              actions: # supported actions for this zone. eg value ["ban", "captcha"]
                - captcha
              default_action: captcha
              routes_to_protect:
                - '*example.com/*'
              turnstile: # Turnstile must be enabled if captcha action is used.
                enabled: true
                rotate_secret_key: true
                rotate_secret_key_every: 168h0m0s
                mode: managed
    
  update_frequency: 30s # the frequency to update the cloudflare IP list 

# Bouncer Config
log_mode: file
log_dir: /var/log/ 
log_level: info # valid choices are either debug, info, error 
log_max_size: 40
log_max_files: 3
log_max_age: 30
compress_logs: true

prometheus:
  enabled: false
  listen_addr: 127.0.0.1
  listen_port: 2112
```

## Cloudflare Configuration

**Background:** In Cloudflare, each user can have access to multiple accounts. Each account can own/access multiple zones. In this context a zone can be considered as a domain. Each domain registered with cloudflare gets a distinct `zone_id`.


For obtaining the `token`:
1. Sign in as a user who has access to the desired account.
2. Go to [Tokens](https://dash.cloudflare.com/profile/api-tokens) and create the token. The bouncer requires the follwing permissions to function.
![image](https://docs.crowdsec.net/assets/images/cloudflare_token_permissions-1fd049cf03d8d2440112b9b7f486b7c4.png)

To automatically generate config for cloudflare check the  helper section below.


:::note
If the zone is subscribed to a paid Cloudflare plan then it can be configured to support multiple types of actions. For free plan zones only one action is supported. The first action is applied as default action.
:::


## Helpers

The bouncer's binary has built in helper scripts to do various operations.

### Auto config generator

Generates bouncer config by discovering all the accounts and the zones associated with provided list of tokens. 

Example Usage:

```bash
docker run crowdsecurity/cloudflare-bouncer -g <TOKEN_1>,<TOKEN_2>... > cfg.yaml
```

After reviewing the config you can bind mount it to the container at path `/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml` as shown in the setup gude.

:::note
This script only generates cloudflare related config. By default it refers to the config at `/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml` for crowdsec configuration. 
:::

Using custom config:
```bash
docker run crowdsecurity/cloudflare-bouncer -c /cfg.yaml -g <TOKEN_1>,<TOKEN_2>...  -v $PWD/cfg.yaml:/cfg.yaml
```

Make sure that the custom config is mounted in the container.

### Cloudflare Setup

This only creates the required IP lists and firewall rules at cloudflare and exits.

Example Usage:
```bash
  docker run \
  -v $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml \
  -p 2112:2112 \
  crowdsecurity/cloudflare-bouncer -s
```

### Cloudflare Cleanup

This deletes all IP lists and firewall rules at cloudflare which were created by the bouncer.

Example Usage:
```bash
  docker run \
  -v $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml \
  -p 2112:2112 \
  crowdsecurity/cloudflare-bouncer -s
```

# How it works

The service polls the CrowdSec Local API for new decisions. It then makes API calls to Cloudflare
to update IP lists and firewall rules depending upon the decision.


# Troubleshooting
 - Metrics are exposed at port 2112