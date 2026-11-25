/**
 * TypeScript type definitions for CrowdSec Cloudflare Worker
 */

/**
 * Environment bindings shared by both compiled decisions-sync workers
 * (kv-sync-worker.js and ip-lists-sync-worker.js). Which one is deployed is
 * chosen at deploy time — there is no runtime flag that switches a single
 * worker between targets.
 */
export interface CrowdSecEnvCommon {
	/**
	 * CrowdSec LAPI base URL
	 * @example "http://localhost:8080"
	 * @example "https://admin.api.crowdsec.net/v1/integrations/YOUR_INTEGRATION_ID"
	 */
	LAPI_URL: string;

	/**
	 * CrowdSec LAPI API key for authentication
	 */
	LAPI_KEY: string;

	/**
	 * Comma-separated list of scenario patterns to include
	 * Only works with self-hosted LAPI (NOT BLaaS)
	 * @optional
	 * @example "crowdsecurity/http-probing,crowdsecurity/ssh-bf"
	 */
	INCLUDE_SCENARIOS?: string;

	/**
	 * Comma-separated list of scenario patterns to exclude
	 * Only works with self-hosted LAPI (NOT BLaaS)
	 * @optional
	 * @example "crowdsecurity/test-scenario"
	 */
	EXCLUDE_SCENARIOS?: string;

	/**
	 * Comma-separated list of decision origins to include
	 * Only works with self-hosted LAPI (NOT BLaaS)
	 * @optional
	 * @example "crowdsec,cscli"
	 */
	ONLY_INCLUDE_ORIGINS?: string;

	/**
	 * Cloudflare KV namespace used for the worker's own state: WARMED_UP, the
	 * sync lock, RESET, and (IP-list worker only) the rate-limit/backoff
	 * deadline. Required by both workers even though only the KV-target
	 * worker stores decision data in it.
	 */
	CROWDSECCFBOUNCERNS: KVNamespace;

	/**
	 * Cloudflare account ID, used for the Cloudflare REST API calls both
	 * workers make (bulk KV endpoints, or IP Lists endpoints).
	 */
	CF_ACCOUNT_ID: string;

	/**
	 * Cloudflare API token, used for the Cloudflare REST API calls both
	 * workers make (bulk KV endpoints, or IP Lists endpoints).
	 */
	CF_API_TOKEN: string;
}

/**
 * Environment bindings for the KV-target worker (kv-sync-worker.js): syncs
 * all decision scopes to the Worker's KV store, the L7 bouncer worker's data
 * source.
 */
export interface CrowdSecEnvKv extends CrowdSecEnvCommon {
	/**
	 * KV namespace ID, used for the bulk KV REST API calls that write/delete
	 * decision data.
	 */
	CF_KV_NAMESPACE_ID: string;
}

/**
 * Environment bindings for the IP-Lists-target worker
 * (ip-lists-sync-worker.js): syncs `ip`/`range` scoped decisions into a
 * single Cloudflare IP List, used for L3/4 firewall-rule bouncing. The list
 * itself and the firewall rule referencing it must be provisioned
 * externally — this worker only manages list membership, stateless:
 * Cloudflare's own list contents are the only source of truth, no D1 or
 * other local index involved.
 *
 * On a startup pull (first run, or the tick right after a RESET or a failed
 * previous startup), the full LAPI decision set is PUT wholesale into the
 * list, replacing its entire contents, and the worker then waits 25h (win or
 * lose) before any further IP-list action — a failed startup leaves
 * WARMED_UP unset, so it simply retries as a startup once the wait clears.
 * Once warmed, each tick instead applies just that tick's new/expired
 * decisions via plain add (POST) and remove (DELETE) calls — item ids for
 * removals are resolved by reading the list's current contents first.
 * Decisions beyond IP_LIST_MAX_ITEMS_PER_LIST are dropped for that tick
 * (logged) rather than queued — there is no local state to retry them from,
 * so they're picked up again only by the next startup pull.
 */
export interface CrowdSecEnvIpLists extends CrowdSecEnvCommon {
	/**
	 * When "true", bypasses the normal startup/warmed sync entirely: each
	 * tick does a full LAPI startup pull and PUTs only the first 10
	 * ip/range-scoped IPs into a fixed list named "crowdsec_test" (must
	 * already exist — this mode never creates it), logging how many were put
	 * successfully. For sanity-checking CF_ACCOUNT_ID/CF_API_TOKEN access
	 * against a small, non-traffic-facing list without risking real lists.
	 * @optional
	 * @default "false"
	 */
	TEST_MODE?: string;

	/**
	 * Name prefix used to discover which Cloudflare IP List this worker is
	 * allowed to manage.
	 * @optional
	 * @default "crowdsec_"
	 */
	IP_LIST_PREFIX?: string;

	/**
	 * Ceiling on how many IPs this worker will put into its managed list.
	 * Cloudflare's large "IP Lists" have no fixed per-list item cap of their
	 * own, so this is purely an operator choice — override it if you want a
	 * smaller/larger limit than the built-in default.
	 * @optional
	 * @default "300000"
	 */
	IP_LIST_MAX_ITEMS_PER_LIST?: string;
}

/**
 * Union of both workers' environments, for shared code (core/, utils/) that
 * doesn't care which target it's running under.
 */
export type CrowdSecEnv = CrowdSecEnvKv | CrowdSecEnvIpLists;

/**
 * Decision scope types supported by CrowdSec
 */
export type DecisionScope = 'ip' | 'range' | 'as' | 'country';

/**
 * Decision action types
 */
export type DecisionAction = 'ban' | 'captcha';

/**
 * CrowdSec decision object from LAPI
 */
export interface Decision {
	/**
	 * Unique decision ID
	 */
	id: number;

	/**
	 * Decision origin
	 * @example "crowdsec"
	 * @example "cscli"
	 */
	origin: string;

	/**
	 * Decision type/action
	 */
	type: DecisionAction;

	/**
	 * Decision scope
	 */
	scope: DecisionScope;

	/**
	 * Decision value (IP, CIDR range, AS, or country code)
	 * @example "192.168.1.1" (for scope: ip)
	 * @example "192.168.0.0/16" (for scope: range)
	 * @example "12345" (for scope: as)
	 * @example "US" (for scope: country)
	 */
	value: string;

	/**
	 * Scenario that triggered the decision
	 * @example "crowdsecurity/ssh-bruteforce"
	 */
	scenario: string;

	/**
	 * Decision duration
	 * @example "4h"
	 */
	duration: string;

	/**
	 * Expiration timestamp (ISO 8601)
	 * @example "2025-10-17T12:00:00Z"
	 */
	until: string;
}

/**
 * Streaming decision response
 */
export interface DecisionStreamResponse {
	/**
	 * New decisions to add
	 */
	new: Decision[];

	/**
	 * Deleted decisions to remove
	 */
	deleted: Decision[];
}

/**
 * IP ranges object stored in KV under "IP_RANGES" key
 */
export interface IpRanges {
	[cidr: string]: DecisionAction;
}

/**
 * KV entry for batch write operations
 */
export interface KVEntry {
	key: string;
	value: string;
}
