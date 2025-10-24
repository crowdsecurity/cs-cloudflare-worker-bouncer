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
