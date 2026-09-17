/**
 * TypeScript type definitions for CrowdSec Cloudflare Worker
 */

/**
 * CrowdSec environment bindings
 * Contains all configuration variables and Cloudflare resource bindings
 */
export interface CrowdSecEnv {
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
	 * Cloudflare KV namespace for storing CrowdSec decisions
	 */
	CROWDSECCFBOUNCERNS: KVNamespace;

	/**
	 * Whether to sync decisions to the Worker's KV store (used by the L7
	 * bouncer worker). Defaults to enabled; set to "false" to disable.
	 * @optional
	 * @default "true"
	 */
	SYNC_TO_KV?: string;

	/**
	 * Whether to sync 'ip'/'range' scoped decisions to Cloudflare IP Lists
	 * (used for L3/4 firewall-rule bouncing). Defaults to disabled; set to
	 * "true" to enable. List creation and the firewall rules referencing
	 * those lists must be provisioned externally — this worker only manages
	 * list membership.
	 * @optional
	 * @default "false"
	 */
	SYNC_TO_IP_LISTS?: string;

	/**
	 * Name prefix used to discover which Cloudflare IP Lists this worker is
	 * allowed to manage. Only used when SYNC_TO_IP_LISTS is enabled.
	 * @optional
	 * @default "crowdsec_"
	 */
	IP_LIST_PREFIX?: string;

	/**
	 * D1 database backing the IP list sync queue (a single `ip_list_queue`
	 * table: pending new/expired decisions, keyed by ip). Required when
	 * SYNC_TO_IP_LISTS is enabled.
	 */
	CROWDSECCFBOUNCER_QUEUE_DB?: D1Database;

	/**
	 * Maximum number of queued rows (a mix of pending adds and removals)
	 * processed against Cloudflare IP Lists per sync tick. Bounding this
	 * keeps each tick's Cloudflare API usage predictable regardless of how
	 * large the backlog is — a large warmup (e.g. 100k+ IPs) drains over
	 * many ticks rather than in one burst. Only used when SYNC_TO_IP_LISTS
	 * is enabled.
	 * @optional
	 * @default "1000"
	 */
	IP_LIST_BATCH_SIZE?: string;
}

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
