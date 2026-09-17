
;// ./src/utils/logger.js
/**
 * Simple structured logger
 * Provides consistent logging format with timestamps
 */

const LOG_LEVELS = {
	DEBUG: 'DEBUG',
	INFO: 'INFO',
	WARN: 'WARN',
	ERROR: 'ERROR',
};

/**
 * Format a log message with timestamp and level
 * @param {string} level - Log level (DEBUG, INFO, WARN, ERROR)
 * @param {string} message - Main log message
 * @param {Object} context - Optional context object to include in log
 * @returns {string} Formatted log message
 */
function formatLog(level, message, context = {}) {
	const timestamp = new Date().toISOString();
	const contextStr = Object.keys(context).length > 0 ? ` ${JSON.stringify(context)}` : '';
	return `[${timestamp}] [${level}] ${message}${contextStr}`;
}

/**
 * Log a debug message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data
 */
function debug(message, context = {}) {
	console.log(formatLog(LOG_LEVELS.DEBUG, message, context));
}

/**
 * Log an info message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data
 */
function info(message, context = {}) {
	console.log(formatLog(LOG_LEVELS.INFO, message, context));
}

/**
 * Log a warning message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data
 */
function warn(message, context = {}) {
	console.warn(formatLog(LOG_LEVELS.WARN, message, context));
}

/**
 * Log an error message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data (can include error object)
 */
function error(message, context = {}) {
	console.error(formatLog(LOG_LEVELS.ERROR, message, context));
}

/* harmony default export */ const logger = ({
	debug,
	info,
	warn,
	error,
});

;// ./src/core/decision-fetcher.js
/**
 * CrowdSec LAPI Decision Fetcher
 * Fetches security decisions from CrowdSec LAPI or BLaaS endpoint
 * Based on the Node.js bouncer implementation pattern
 */



const USER_AGENT = 'cloudflare-worker-bouncer/v1.0.0';
const WARMED_UP_KEY = 'WARMED_UP';
const SYNC_LOCK_KEY = 'SYNC_IN_PROGRESS';
// TTL backstop in case a sync crashes before releaseSyncLock runs; without
// this, a stuck lock would block every subsequent cron run.
const SYNC_LOCK_TTL_SECONDS = 300;
const SUPPORTED_SCOPES = ['ip', 'range', 'as', 'country'];

/**
 * Check if this is the first fetch by looking for the WARMED_UP flag in KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<boolean>} True if this is the first fetch
 */
async function isFirstFetch(kvNamespace) {
	const warmedUpFlag = await kvNamespace.get(WARMED_UP_KEY);
	return !warmedUpFlag;
}

/**
 * Mark the cache as warmed up. MUST only be called after a sync has fully
 * written all decisions to KV — calling it before commits a half-empty KV
 * to "warmed" state, causing the next run to do an incremental fetch that
 * never backfills the missed decisions (silent enforcement gap).
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 */
async function markAsWarmed(kvNamespace) {
	await kvNamespace.put(WARMED_UP_KEY, 'true');
	logger.debug('Cache marked as warmed');
}

/**
 * Try to acquire the sync lock. Returns true if acquired, false if another
 * sync is already running. Caller MUST call releaseSyncLock in a finally
 * block. The TTL is a backstop only — do not rely on it for normal release.
 *
 * NOTE: Workers KV has no atomic put-if-absent, so this is a best-effort
 * advisory lock. A small race window exists between get() and put() where
 * two near-simultaneous invocations can both observe `existing === null`
 * and both proceed. With a 5-minute cron interval it's unlikely; LAPI's
 * own rate limiting is the actual safety net against a sync storm.
 *
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<boolean>} True if the lock was acquired
 */
async function tryAcquireSyncLock(kvNamespace) {
	const existing = await kvNamespace.get(SYNC_LOCK_KEY);
	if (existing) {
		return false;
	}
	await kvNamespace.put(SYNC_LOCK_KEY, 'true', { expirationTtl: SYNC_LOCK_TTL_SECONDS });
	return true;
}

/**
 * Release the sync lock acquired via tryAcquireSyncLock.
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 */
async function releaseSyncLock(kvNamespace) {
	await kvNamespace.delete(SYNC_LOCK_KEY);
}

/**
 * Build query parameters for the decisions stream endpoint
 * @param {Object} options - Fetch options
 * @param {boolean} [options.startup] - Whether this is the first fetch
 * @param {import('../types.js').DecisionScope[]} [options.scopes] - Decision scopes to filter (default: ['ip', 'range', 'as', 'country'])
 * @param {string[]} [options.scenariosContaining] - Filter decisions by scenarios containing these strings
 * @param {string[]} [options.scenariosNotContaining] - Exclude decisions by scenarios containing these strings
 * @param {string[]} [options.origins] - Filter decisions by origin
 * @returns {URLSearchParams}
 */
function buildQueryParams(options) {
	const { startup = false, scopes = SUPPORTED_SCOPES, scenariosContaining = [], scenariosNotContaining = [], origins = [] } = options;

	const params = new URLSearchParams({
		startup: startup.toString(),
	});

	// Only include supported scopes (ip, range, as, country)
	const validScopes = scopes.filter((scope) => SUPPORTED_SCOPES.includes(scope));
	if (validScopes.length > 0) {
		params.append('scopes', validScopes.join(','));
	}

	if (origins.length > 0) {
		params.append('origins', origins.join(','));
	}

	if (scenariosContaining.length > 0) {
		params.append('scenarios_containing', scenariosContaining.join(','));
	}

	if (scenariosNotContaining.length > 0) {
		params.append('scenarios_not_containing', scenariosNotContaining.join(','));
	}

	return params;
}

/**
 * Validate a decision object structure
 * @param {import('../types.js').Decision} decision - Decision object to validate
 * @returns {boolean} True if valid
 */
function isValidDecision(decision) {
	return (
		decision &&
		typeof decision.origin === 'string' &&
		typeof decision.type === 'string' &&
		typeof decision.scope === 'string' &&
		typeof decision.value === 'string' &&
		typeof decision.duration === 'string' &&
		typeof decision.scenario === 'string'
	);
}

/**
 * Normalize and filter decisions
 * Normalizes scope to lowercase and filters out invalid/unsupported decisions
 * @param {import('../types.js').Decision[]} decisions - Array of decision objects
 * @returns {import('../types.js').Decision[]} Normalized and filtered decisions
 */
function normalizeAndFilterDecisions(decisions) {
	if (!Array.isArray(decisions)) {
		return [];
	}

	return decisions
		.map((decision) => {
			// Normalize scope to lowercase (CrowdSec may return "Range" instead of "range")
			if (decision && decision.scope) {
				decision.scope = decision.scope.toLowerCase();
			}
			return decision;
		})
		.filter((decision) => {
			if (!isValidDecision(decision)) {
				logger.warn('Invalid decision object detected, skipping', { decision });
				return false;
			}

			if (!SUPPORTED_SCOPES.includes(decision.scope)) {
				logger.debug(`Unsupported scope "${decision.scope}" for decision, skipping`, { value: decision.value });
				return false;
			}

			return true;
		});
}

/**
 * Fetch decisions from CrowdSec LAPI using the stream endpoint
 * @param {string} lapiUrl - Base URL of the LAPI (e.g., "https://lapi.example.com")
 * @param {string} apiKey - API key for authentication
 * @param {Object} [options] - Fetch options
 * @param {boolean} [options.startup] - Whether this is the first fetch (startup=true gets all decisions)
 * @param {import('../types.js').DecisionScope[]} [options.scopes] - Decision scopes to filter (default: ['ip', 'range', 'as', 'country'])
 * @param {string[]} [options.scenariosContaining] - Filter by scenarios containing these strings
 * @param {string[]} [options.scenariosNotContaining] - Exclude scenarios containing these strings
 * @param {string[]} [options.origins] - Filter by decision origins
 * @returns {Promise<import('../types.js').DecisionStreamResponse>} Object with new and deleted decisions
 * @throws {Error} If the LAPI request fails
 */
async function fetchDecisionsStream(lapiUrl, apiKey, options = {}) {
	const params = buildQueryParams(options);
	const fullUrl = `${lapiUrl}/v1/decisions/stream?${params.toString()}`;

	logger.debug('Fetching decisions from LAPI', { url: fullUrl });

	const response = await fetch(fullUrl, {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json',
			'X-Api-Key': apiKey,
			'User-Agent': USER_AGENT,
		},
	});

	if (!response.ok) {
		const errorText = await response.text().catch(() => 'Unknown error');
		throw new Error(`LAPI request failed with status ${response.status}: ${errorText}`);
	}

	// Handle HTTP 204 No Content (LAPI has no decisions - need to delete all from KV)
	if (response.status === 204) {
		logger.info('LAPI returned 204 No Content: LAPI has no decisions, will clear KV');
		return {
			new: [],
			deleted: [],
			deleteAll: true, // Signal to main sync logic to reset KV and exit
		};
	}

	const data = await response.json();

	// Validate response structure
	if (!data || typeof data !== 'object') {
		throw new Error('Invalid response format from LAPI');
	}

	// Extract new and deleted decisions
	const newDecisions = data.new || [];
	const deletedDecisions = data.deleted || [];

	// Filter to only include valid and supported decisions
	const filteredNew = normalizeAndFilterDecisions(newDecisions);
	const filteredDeleted = normalizeAndFilterDecisions(deletedDecisions);

	logger.info('Decisions fetched successfully', {
		newTotal: newDecisions.length,
		newFiltered: filteredNew.length,
		deletedTotal: deletedDecisions.length,
		deletedFiltered: filteredDeleted.length,
		startup: options.startup,
	});

	return {
		new: filteredNew,
		deleted: filteredDeleted,
	};
}

;// ./src/core/decision-processor.js
/**
 * Decision Processor
 * Processes CrowdSec decisions and prepares them for KV storage
 */



// String-based scopes (stored as individual KV entries)
const STRING_SCOPES = ['ip', 'as', 'country'];

/**
 * Helper function to process string-based decisions (IP, AS, Country)
 * @param {import('../types.js').Decision} decision - Decision object
 * @param {Map<string, string>} existingStringDecisions - Existing decisions map
 * @param {import('../types.js').KVEntry[]} stringEntries - Array to push new/updated entries
 * @param {import('../types.js').DecisionScope} scope - Scope name (ip, as, country)
 */
function processStringDecision(decision, existingStringDecisions, stringEntries, scope) {
	// Normalize key based on scope
	const key = scope === 'country' ? decision.value.toLowerCase() : decision.value;
	const value = decision.type; // "ban" or "captcha"

	const existing = existingStringDecisions.get(key);

	if (!existing || existing !== value) {
		// New decision or remediation changed - write to KV
		stringEntries.push({ key, value });
	}
	// If exists with same remediation - no update needed
}

/**
 * Process new decisions and prepare KV entries
 * @param {import('../types.js').Decision[]} decisions - Array of decision objects from LAPI
 * @param {Map<string, string>} existingStringDecisions - Map of existing string KV entries (key -> value) for IP/AS/Country
 * @param {import('../types.js').IpRanges} existingRanges - Existing IP_RANGES object from KV
 * @returns {{stringEntries: import('../types.js').KVEntry[], jsonEntries: import('../types.js').IpRanges}} Processed decisions ready for KV sync
 */
function processNewDecisions(decisions, existingStringDecisions, existingRanges) {
	const stringEntries = []; // Individual KV entries: IP, AS, Country
	const jsonEntries = {}; // Aggregated JSON entries: Ranges

	for (const decision of decisions) {
		if (STRING_SCOPES.includes(decision.scope)) {
			// Handle string-based decisions (IP, AS, Country) - stored as individual KV entries
			processStringDecision(decision, existingStringDecisions, stringEntries, decision.scope);
		} else if (decision.scope === 'range') {
			// Handle Range scoped decisions - stored in IP_RANGES JSON object
			const cidr = decision.value; // CIDR notation (e.g., "192.168.0.0/16")
			const remediation = decision.type; // "ban" or "captcha"

			const existing = existingRanges[cidr];

			if (!existing || existing !== remediation) {
				// New range or remediation changed - add to jsonEntries
				jsonEntries[cidr] = remediation;
			} else {
				// Range exists with same remediation - keep it in the new ranges object
				jsonEntries[cidr] = remediation;
			}
		}
	}

	return {
		stringEntries,
		jsonEntries,
	};
}

/**
 * Helper function to process string-based decision deletions (IP, AS, Country)
 * @param {import('../types.js').Decision} decision - Decision object to delete
 * @param {Map<string, string>} existingStringDecisions - Existing decisions map
 * @param {string[]} stringKeysToDelete - Array to push keys to delete
 * @param {import('../types.js').DecisionScope} scope - Scope name (ip, as, country)
 */
function processStringDeletion(decision, existingStringDecisions, stringKeysToDelete, scope) {
	// Normalize key based on scope
	const key = scope === 'country' ? decision.value.toLowerCase() : decision.value;
	const expectedValue = decision.type;

	const existing = existingStringDecisions.get(key);

	if (existing && existing === expectedValue) {
		// Only delete if it exists AND has the same remediation type
		stringKeysToDelete.push(key);
	}
	// Skip if not found or remediation differs (already handled elsewhere or updated)
}

/**
 * Process deleted decisions and prepare keys for deletion
 * @param {import('../types.js').Decision[]} decisions - Array of decision objects to delete from LAPI
 * @param {Map<string, string>} existingStringDecisions - Map of existing string KV entries (key -> value) for IP/AS/Country
 * @param {import('../types.js').IpRanges} existingRanges - Existing IP_RANGES object from KV
 * @returns {{stringKeysToDelete: string[], updatedRanges: import('../types.js').IpRanges}} Keys to delete and updated ranges
 */
function processDeletedDecisions(decisions, existingStringDecisions, existingRanges) {
	const stringKeysToDelete = []; // Keys to delete for IP, AS, Country
	const updatedRanges = { ...existingRanges }; // Start with existing ranges

	for (const decision of decisions) {
		if (STRING_SCOPES.includes(decision.scope)) {
			// Handle string-based decision deletions (IP, AS, Country)
			processStringDeletion(decision, existingStringDecisions, stringKeysToDelete, decision.scope);
		} else if (decision.scope === 'range') {
			// Handle Range scoped decisions
			const cidr = decision.value;
			const expectedRemediation = decision.type;

			const existing = existingRanges[cidr];

			if (existing && existing === expectedRemediation) {
				// Only delete if it exists AND has the same remediation type
				delete updatedRanges[cidr];
			}
			// Skip if not found or remediation differs
		}
	}

	return {
		stringKeysToDelete,
		updatedRanges,
	};
}

/**
 * Merge ranges from two sources (later ranges override earlier ones)
 * @param {import('../types.js').IpRanges} baseRanges - Base ranges (e.g., ranges with deletions applied)
 * @param {import('../types.js').IpRanges} additionalRanges - Additional ranges to merge in (e.g., new ranges from decisions)
 * @returns {import('../types.js').IpRanges} Merged ranges object
 */
function mergeRanges(baseRanges, additionalRanges) {
	return {
		...baseRanges,
		...additionalRanges,
	};
}

/**
 * Check if IP_RANGES needs updating
 * @param {import('../types.js').IpRanges} oldRanges - Old IP_RANGES
 * @param {import('../types.js').IpRanges} newRanges - New IP_RANGES
 * @returns {boolean} True if ranges changed
 */
function hasRangesChanged(oldRanges, newRanges) {
	const oldKeys = Object.keys(oldRanges).sort();
	const newKeys = Object.keys(newRanges).sort();

	// Check if number of ranges changed
	if (oldKeys.length !== newKeys.length) {
		return true;
	}

	// Check if any key is different
	for (let i = 0; i < oldKeys.length; i++) {
		if (oldKeys[i] !== newKeys[i]) {
			return true;
		}

		// Check if value for this key changed
		if (oldRanges[oldKeys[i]] !== newRanges[newKeys[i]]) {
			return true;
		}
	}

	return false;
}

;// ./src/adapters/cloudflare-kv.js
/**
 * Cloudflare KV Adapter
 * Handles batch read/write/delete operations for Cloudflare KV store
 * Uses Cloudflare REST API bulk endpoints to minimize operation count
 */



const BATCH_SIZE = 10000; // Cloudflare KV limit for bulk write/delete operations
const BATCH_SIZE_GET = 100; // Cloudflare KV limit for bulk get operations
const IP_RANGES_KEY = 'IP_RANGES';
const RESET_KEY = 'RESET';
// Keys to preserve during reset
const PRESERVED_KEYS = ['BAN_TEMPLATE', 'TURNSTILE_CONFIG'];

/**
 * Build headers for Cloudflare API requests
 * @param {string} apiToken - Cloudflare API token
 * @returns {Object} Headers object
 */
function buildApiHeaders(apiToken) {
	return {
		'Authorization': `Bearer ${apiToken}`,
		'Content-Type': 'application/json',
	};
}

/**
 * Write decisions to KV using bulk API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {import('../types.js').KVEntry[]} entries - Entries to write
 * @returns {Promise<number>} Number of entries written
 */
async function batchWriteStringBasedDecisions(accountId, namespaceId, apiToken, entries) {
	if (!entries || entries.length === 0) {
		logger.debug('No entries to write to KV');
		return 0;
	}

	let written = 0;

	logger.debug(`Writing ${entries.length} entries to KV using bulk API`);

	// Process in batches of BATCH_SIZE (10,000 max per bulk request)
	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(entries.length / BATCH_SIZE);

		logger.debug(`Writing bulk batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalEntries: entries.length,
		});

        // See https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/methods/bulk_update/
		const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/bulk`;

		const response = await fetch(url, {
			method: 'PUT',
			headers: buildApiHeaders(apiToken),
			body: JSON.stringify(batch),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Bulk write failed (batch ${batchNum}): ${response.status} ${errorText}`);
		}

		written += batch.length;
		logger.debug(`Bulk batch ${batchNum}/${totalBatches} written successfully`);
	}

	logger.debug(`Wrote ${written} entries to KV successfully`);

	return written;
}

/**
 * Delete decisions from KV using bulk API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {string[]} keys - Keys to delete
 * @returns {Promise<number>} Number of entries deleted
 */
async function batchDeleteStringBasedDecisions(accountId, namespaceId, apiToken, keys) {
	if (!keys || keys.length === 0) {
		logger.debug('No keys to delete from KV');
		return 0;
	}

	let deleted = 0;

	logger.debug(`Deleting ${keys.length} keys from KV using bulk API`);

	// Process in batches of BATCH_SIZE (10,000 max per bulk request)
	for (let i = 0; i < keys.length; i += BATCH_SIZE) {
		const batch = keys.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(keys.length / BATCH_SIZE);

		logger.debug(`Deleting bulk batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalKeys: keys.length,
		});

        // See https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/methods/bulk_delete/
		const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/bulk/delete`;

		const response = await fetch(url, {
			method: 'POST',
			headers: buildApiHeaders(apiToken),
			body: JSON.stringify(batch),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Bulk delete failed (batch ${batchNum}): ${response.status} ${errorText}`);
		}

		deleted += batch.length;
		logger.debug(`Bulk batch ${batchNum}/${totalBatches} deleted successfully`);
	}

	logger.debug(`Deleted ${deleted} keys from KV successfully`);

	return deleted;
}

/**
 * Get the current IP_RANGES object from KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<import('../types.js').IpRanges>} IP ranges object (CIDR -> remediation)
 */
async function getIpRanges(kvNamespace) {
	try {
		const rangesJson = await kvNamespace.get(IP_RANGES_KEY);
		if (!rangesJson) {
			logger.debug('No IP_RANGES found in KV, returning empty object');
			return {};
		}

		const ranges = JSON.parse(rangesJson);
		logger.debug('Fetched IP_RANGES from KV', { count: Object.keys(ranges).length });
		return ranges;
	} catch (error) {
		logger.error('Failed to parse IP_RANGES from KV', { error: error.message });
		return {};
	}
}

/**
 * Write the IP_RANGES object to KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @param {import('../types.js').IpRanges} ranges - IP ranges object (CIDR -> remediation)
 * @returns {Promise<void>}
 */
async function writeIpRanges(kvNamespace, ranges) {
	const rangesJson = JSON.stringify(ranges);
	await kvNamespace.put(IP_RANGES_KEY, rangesJson);
}

/**
 * Get multiple keys from KV using bulk API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {string[]} keys - Keys to fetch
 * @returns {Promise<Map<string, string>>} Map of key -> value for existing entries
 */
async function batchGetStringBasedDecisions(accountId, namespaceId, apiToken, keys) {
	if (!keys || keys.length === 0) {
		return new Map();
	}

	logger.debug(`Fetching ${keys.length} keys (ip, as or country) from KV using bulk API`);

	const existingMap = new Map();

	// Process in batches of BATCH_SIZE_GET (100 max per bulk get request)
	for (let i = 0; i < keys.length; i += BATCH_SIZE_GET) {
		const batch = keys.slice(i, i + BATCH_SIZE_GET);
		const batchNum = Math.floor(i / BATCH_SIZE_GET) + 1;
		const totalBatches = Math.ceil(keys.length / BATCH_SIZE_GET);

		logger.debug(`Fetching bulk batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalKeys: keys.length,
		});
        // See https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/methods/bulk_get/
		const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/bulk/get`;

		const response = await fetch(url, {
			method: 'POST',
			headers: buildApiHeaders(apiToken),
			body: JSON.stringify({ keys: batch }),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Bulk get failed (batch ${batchNum}): ${response.status} ${errorText}`);
		}

		const data = await response.json();

		// Build map of existing entries
		// API returns: {success: true, result: {values: {key1: value1, key2: value2}}}
		if (data.result && data.result.values) {
			for (const [key, value] of Object.entries(data.result.values)) {
				if (value !== null) {
					existingMap.set(key, value);
				}
			}
		}

		logger.debug(`Bulk batch ${batchNum}/${totalBatches} fetched successfully`);
	}

	logger.debug(`Found ${existingMap.size} existing entries in KV out of ${keys.length} requested`);

	return existingMap;
}

/**
 * Check if reset is requested
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<boolean>} True if RESET key exists and is set to 'true'
 */
async function shouldReset(kvNamespace) {
	try {
		const resetValue = await kvNamespace.get(RESET_KEY);
		return resetValue === 'true';
	} catch (error) {
		logger.error('Failed to check RESET key', { error: error.message });
		return false;
	}
}

/**
 * Clear the RESET flag. resetAllDecisions already does this as part of
 * clearing KV, but callers that honor RESET without KV sync enabled (e.g.
 * IP-list-only mode) must clear it explicitly, or a manual RESET=true would
 * otherwise never be acknowledged and would keep re-triggering every tick.
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 */
async function clearResetFlag(kvNamespace) {
	await kvNamespace.put(RESET_KEY, 'false');
}

/**
 * List all keys in KV namespace using Cloudflare API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @returns {Promise<string[]>} Array of all key names in the namespace
 */
async function listAllKeys(accountId, namespaceId, apiToken) {
	const allKeys = [];
	let cursor = null;

	logger.debug('Listing all keys in KV namespace...');

	do {
        // See https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/subresources/keys/methods/list/
		const url = cursor
			? `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/keys?cursor=${cursor}`
			: `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/keys`;

		const response = await fetch(url, {
			method: 'GET',
			headers: buildApiHeaders(apiToken),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Failed to list KV keys: ${response.status} ${errorText}`);
		}

		const data = await response.json();

		if (data.result && data.result.length > 0) {
			allKeys.push(...data.result.map((item) => item.name));
		}

		cursor = data.result_info?.cursor || null;
	} while (cursor);

	logger.debug(`Listed ${allKeys.length} total keys in KV namespace`);

	return allKeys;
}

/**
 * Reset all decision keys in KV while preserving BAN_TEMPLATE and TURNSTILE_CONFIG
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace (for direct operations)
 * @returns {Promise<void>}
 */
async function resetAllDecisions(accountId, namespaceId, apiToken, kvNamespace) {
	logger.info('Starting KV reset: deleting all decision keys...');

	// Step 1: List all keys in KV
	const allKeys = await listAllKeys(accountId, namespaceId, apiToken);

	// Step 2: Filter keys to delete (all except preserved keys and RESET itself)
	const keysToDelete = allKeys.filter(
		(key) => !PRESERVED_KEYS.includes(key) && key !== RESET_KEY
	);

	logger.info(`Found ${keysToDelete.length} keys to delete (preserving ${PRESERVED_KEYS.join(', ')})`);

	// Step 3: Delete all decision keys using bulk operations
	if (keysToDelete.length > 0) {
		await batchDeleteStringBasedDecisions(accountId, namespaceId, apiToken, keysToDelete);
	}

	// Step 4: Set RESET to false
	await kvNamespace.put(RESET_KEY, 'false');
	logger.info('RESET key set to false');

	logger.info('KV reset completed successfully');
}

;// ./src/adapters/cloudflare-ip-lists.js
/**
 * Cloudflare IP Lists Adapter
 * Manages membership of CrowdSec-prefixed IP Lists for L3/4 (firewall rule)
 * bouncing. List creation and the firewall rules that reference these lists
 * are provisioned by an external process — this adapter only fills/empties
 * list membership.
 *
 * New and expired decisions are never applied to Cloudflare directly: they're
 * queued in a D1 table first (see the QUEUE_* functions below), and a bounded
 * batch is drained from the queue each sync tick. This lets warmup (which can
 * take days at realistic decision volumes) make steady, resumable progress
 * without ever overwriting IPs that some other process manually added to the
 * same lists — an append-only add and an id-targeted remove never touch
 * anything the worker didn't itself queue.
 *
 * Per-list membership is tracked in a sharded KV index (one key per list) so
 * that a single JSON blob never has to hold the whole account's IP set — see
 * IDX_KEY_PREFIX below. Each entry also carries Cloudflare's internal item
 * id, since removing a specific IP requires that id, not the IP itself (see
 * removeListItems).
 */



const IDX_KEY_PREFIX = 'IPLIST_IDX_';
// Holds a single ISO timestamp: don't attempt IP list writes again until
// after this time. Set when Cloudflare returns 429 with a Retry-After we can
// trust; checked at the start of the next sync so we don't burn a cron tick
// re-attempting a call we already know will be rejected.
const BACKOFF_UNTIL_KEY = 'IPLIST_BACKOFF_UNTIL';
// Hard Cloudflare ceiling for a single custom list.
const MAX_ITEMS_PER_LIST = 10000;
const BULK_POLL_INTERVAL_MS = 1000;
const BULK_POLL_TIMEOUT_MS = 120000;
// D1 caps bound parameters at 100/query; each queue row binds 4 (ip, action,
// until, list_action), so 25 rows is the most that fit in one multi-row
// VALUES statement.
const D1_MAX_ROWS_PER_STATEMENT = 25;

/**
 * Error thrown by list-mutating calls on an HTTP failure, with enough detail
 * for the caller to tell a rate limit (429, with a documented Retry-After)
 * apart from anything else (quota exceeded, malformed request, transient
 * 5xx, ...), which Cloudflare does not otherwise let us distinguish from the
 * response body alone.
 */
class CloudflareApiError extends Error {
	constructor(message, { status, retryAfterSeconds, body }) {
		super(message);
		this.name = 'CloudflareApiError';
		this.status = status;
		this.retryAfterSeconds = retryAfterSeconds;
		this.body = body;
	}
}

/**
 * @param {Response} response
 * @returns {Promise<never>}
 */
async function throwApiError(message, response) {
	const body = await response.text();
	const retryAfterHeader = response.headers.get('retry-after');
	const retryAfterSeconds =
		response.status === 429 && retryAfterHeader !== null ? parseInt(retryAfterHeader, 10) : undefined;
	throw new CloudflareApiError(`${message}: ${response.status} ${body}`, {
		status: response.status,
		retryAfterSeconds,
		body,
	});
}

function cloudflare_ip_lists_buildApiHeaders(apiToken) {
	return {
		'Authorization': `Bearer ${apiToken}`,
		'Content-Type': 'application/json',
	};
}

/**
 * Discover the IP Lists this worker is allowed to manage: every custom list
 * whose name starts with the configured prefix. Lists are sorted by name so
 * pack-to-full placement (list 1 first) is stable across runs.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} prefix
 * @returns {Promise<{id: string, name: string}[]>}
 */
async function listManagedIpLists(accountId, apiToken, prefix) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists`;
	const response = await fetch(url, { method: 'GET', headers: cloudflare_ip_lists_buildApiHeaders(apiToken) });

	if (!response.ok) {
		await throwApiError('Failed to list IP Lists', response);
	}

	const data = await response.json();
	const lists = (data.result || [])
		.filter((list) => list.kind === 'ip' && list.name.startsWith(prefix))
		.map((list) => ({ id: list.id, name: list.name }))
		.sort((a, b) => a.name.localeCompare(b.name));

	logger.debug(`Discovered ${lists.length} managed IP list(s) with prefix "${prefix}"`);

	return lists;
}

/**
 * Read the sharded membership index for every managed list.
 * @param {KVNamespace} kvNamespace
 * @param {{id: string, name: string}[]} lists
 * @returns {Promise<Map<string, Map<string, {itemId: string, action: string, until: string}>>>} listName -> (ip -> entry)
 */
async function readIndex(kvNamespace, lists) {
	const index = new Map();

	await Promise.all(
		lists.map(async (list) => {
			const raw = await kvNamespace.get(IDX_KEY_PREFIX + list.name);
			if (!raw) {
				index.set(list.name, new Map());
				return;
			}
			try {
				const parsed = JSON.parse(raw);
				index.set(list.name, new Map(Object.entries(parsed)));
			} catch (e) {
				logger.error(`Failed to parse IP list index for ${list.name}, treating as empty`, { error: e.message });
				index.set(list.name, new Map());
			}
		})
	);

	return index;
}

/**
 * Persist the membership shard for a single list.
 * @param {KVNamespace} kvNamespace
 * @param {string} listName
 * @param {Map<string, {itemId: string, action: string, until: string}>} members
 */
async function writeIndexShard(kvNamespace, listName, members) {
	const obj = Object.fromEntries(members);
	await kvNamespace.put(IDX_KEY_PREFIX + listName, JSON.stringify(obj));
}

/**
 * Upsert a batch of decisions into the D1 queue table, keyed by ip. A row
 * already queued for the same IP is overwritten in place — e.g. an IP
 * queued as 'new' that expires before ever being pushed just flips to
 * 'delete' rather than getting pushed and immediately removed, and a
 * duplicate 'new' from a repeated LAPI stream poll just refreshes
 * action/until rather than erroring or duplicating.
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 * @param {'new' | 'delete'} listAction
 */
async function upsertQueue(db, items, listAction) {
	if (items.length === 0) return;

	// D1 caps bound parameters at 100/query; each row binds 4, so at most 25
	// rows fit in one multi-row VALUES statement. Chunking this way (rather
	// than one statement per row) keeps a large batch well under D1's
	// queries-per-invocation limit (50 on Free, 1000 on Paid) — e.g. 1000
	// rows becomes 40 statements in one db.batch(), not 1000.
	const chunks = chunk(items, D1_MAX_ROWS_PER_STATEMENT);
	const statements = chunks.map((rows) => {
		const placeholders = rows.map(() => '(?, ?, ?, ?)').join(', ');
		const params = rows.flatMap((item) => [item.ip, item.action, item.until ?? null, listAction]);
		return db
			.prepare(
				`INSERT INTO ip_list_queue (ip, action, until, list_action) VALUES ${placeholders}
				 ON CONFLICT(ip) DO UPDATE SET action = excluded.action, until = excluded.until, list_action = excluded.list_action`
			)
			.bind(...params);
	});

	await db.batch(statements);
}

/**
 * Read up to `limit` queued rows (a mix of 'new' and 'delete' entries).
 * @param {D1Database} db
 * @param {number} limit
 * @returns {Promise<{ip: string, action: string, until: string, listAction: string}[]>}
 */
async function readQueueBatch(db, limit) {
	const result = await db.prepare('SELECT ip, action, until, list_action FROM ip_list_queue LIMIT ?').bind(limit).all();
	return (result.results || []).map((row) => ({
		ip: row.ip,
		action: row.action,
		until: row.until,
		listAction: row.list_action,
	}));
}

/**
 * Remove rows from the queue by ip, once their corresponding Cloudflare
 * write has been confirmed and persisted to the per-list KV index.
 * @param {D1Database} db
 * @param {string[]} ips
 */
async function deleteQueueRows(db, ips) {
	if (ips.length === 0) return;

	// Each bound ip is 1 param, so up to 100 fit in one IN (...) statement —
	// same query-count reasoning as upsertQueue.
	const chunks = chunk(ips, 100);
	const statements = chunks.map((rows) => {
		const placeholders = rows.map(() => '?').join(', ');
		return db.prepare(`DELETE FROM ip_list_queue WHERE ip IN (${placeholders})`).bind(...rows);
	});

	await db.batch(statements);
}

/**
 * Delete every row from the D1 queue table. Used when LAPI reports no
 * decisions at all (HTTP 204), mirroring the KV path's resetAllDecisions.
 * @param {D1Database} db
 */
async function clearQueue(db) {
	await db.prepare('DELETE FROM ip_list_queue').run();
}

/**
 * Split an array into fixed-size chunks.
 * @template T
 * @param {T[]} arr
 * @param {number} size
 * @returns {T[][]}
 */
function chunk(arr, size) {
	const chunks = [];
	for (let i = 0; i < arr.length; i += size) {
		chunks.push(arr.slice(i, i + size));
	}
	return chunks;
}

/**
 * Append items to a list on Cloudflare without touching what's already
 * there, and poll the resulting bulk operation until it completes.
 * Cloudflare allows only one pending bulk operation per account, so callers
 * must await this before starting the next list's update.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @param {string[]} ips
 * @returns {Promise<Map<string, string>>} ip -> Cloudflare item id, for the newly added items
 */
async function addListItems(accountId, apiToken, listId, ips) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`;

	const response = await fetch(url, {
		method: 'POST',
		headers: cloudflare_ip_lists_buildApiHeaders(apiToken),
		body: JSON.stringify(ips.map((ip) => ({ ip }))),
	});

	if (!response.ok) {
		await throwApiError(`Failed to add items to list ${listId}`, response);
	}

	const data = await response.json();
	const operationId = data.result?.operation_id;
	if (operationId) {
		await pollBulkOperation(accountId, apiToken, operationId);
	}

	return resolveItemIds(accountId, apiToken, listId, ips);
}

/**
 * Remove items from a list by Cloudflare item id, and poll the resulting
 * bulk operation until it completes.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @param {string[]} itemIds
 */
async function removeListItems(accountId, apiToken, listId, itemIds) {
	if (itemIds.length === 0) return;

	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`;

	const response = await fetch(url, {
		method: 'DELETE',
		headers: cloudflare_ip_lists_buildApiHeaders(apiToken),
		body: JSON.stringify({ items: itemIds.map((id) => ({ id })) }),
	});

	if (!response.ok) {
		await throwApiError(`Failed to remove items from list ${listId}`, response);
	}

	const data = await response.json();
	const operationId = data.result?.operation_id;
	if (operationId) {
		await pollBulkOperation(accountId, apiToken, operationId);
	}
}

/**
 * Cloudflare's add-items response doesn't echo back which item id was
 * assigned to which IP, so after an add completes we page through the
 * list's current items to resolve ip -> item id for just the IPs we added.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @param {string[]} ips - the IPs we just added, to resolve ids for
 * @returns {Promise<Map<string, string>>}
 */
async function resolveItemIds(accountId, apiToken, listId, ips) {
	const wanted = new Set(ips);
	const found = new Map();
	let cursor = null;

	do {
		const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`);
		if (cursor) url.searchParams.set('cursor', cursor);

		const response = await fetch(url, { method: 'GET', headers: cloudflare_ip_lists_buildApiHeaders(apiToken) });
		if (!response.ok) {
			await throwApiError(`Failed to read back items for list ${listId}`, response);
		}

		const data = await response.json();
		for (const item of data.result || []) {
			if (wanted.has(item.ip)) {
				found.set(item.ip, item.id);
			}
		}

		cursor = found.size < wanted.size ? data.result_info?.cursor || null : null;
	} while (cursor);

	if (found.size < wanted.size) {
		const missing = [...wanted].filter((ip) => !found.has(ip));
		logger.error(`Could not resolve Cloudflare item id for ${missing.length} added IP(s) on list ${listId}`, { missing });
	}

	return found;
}

/**
 * Poll a bulk-operation status endpoint until it completes or fails.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} operationId
 */
async function pollBulkOperation(accountId, apiToken, operationId) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/bulk_operations/${operationId}`;
	const deadline = Date.now() + BULK_POLL_TIMEOUT_MS;

	while (Date.now() < deadline) {
		const response = await fetch(url, { method: 'GET', headers: cloudflare_ip_lists_buildApiHeaders(apiToken) });
		if (!response.ok) {
			await throwApiError(`Failed to poll bulk operation ${operationId}`, response);
		}

		const data = await response.json();
		const status = data.result?.status;

		if (status === 'completed') {
			return;
		}
		if (status === 'failed') {
			throw new Error(`Bulk operation ${operationId} failed: ${data.result?.error || 'unknown error'}`);
		}

		await new Promise((resolve) => setTimeout(resolve, BULK_POLL_INTERVAL_MS));
	}

	throw new Error(`Timed out waiting for bulk operation ${operationId} to complete`);
}

/**
 * Read the current IP-list backoff deadline, if any.
 * @param {KVNamespace} kvNamespace
 * @returns {Promise<Date | null>} null if there's no active backoff
 */
async function getBackoffUntil(kvNamespace) {
	const raw = await kvNamespace.get(BACKOFF_UNTIL_KEY);
	if (!raw) return null;

	const until = new Date(raw);
	if (Number.isNaN(until.getTime())) return null;

	return until;
}

/**
 * Record that IP list writes should not be attempted again until the given
 * number of seconds from now — set after a 429 with a Retry-After header.
 * @param {KVNamespace} kvNamespace
 * @param {number} retryAfterSeconds
 */
async function setBackoff(kvNamespace, retryAfterSeconds) {
	const until = new Date(Date.now() + retryAfterSeconds * 1000);
	await kvNamespace.put(BACKOFF_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the backoff deadline, e.g. once it has passed or a sync run
 * completes without hitting a rate limit.
 * @param {KVNamespace} kvNamespace
 */
async function clearBackoff(kvNamespace) {
	await kvNamespace.delete(BACKOFF_UNTIL_KEY);
}



;// ./src/core/ip-list-processor.js
/**
 * IP List Processor
 * Pure planning logic for the D1-queue-based Cloudflare IP List sync (L3/4
 * bouncing). Only 'ip' and 'range' scoped decisions apply here — country/AS
 * decisions aren't representable in a Cloudflare IP List.
 *
 * Each tick: new/expired decisions are upserted into the D1 queue table
 * (list_action = 'new'|'delete'), then a bounded batch of queue rows —
 * whichever kind — is read back and split into a delete plan (against the
 * current per-list index) and an add plan (packed into lists in order, list
 * 1 filled to capacity before list 2 is touched).
 */



const IP_LIST_SCOPES = ['ip', 'range'];

/**
 * Filter a decision batch down to the scopes an IP List can represent.
 * @param {import('../types.js').Decision[]} decisions
 * @returns {import('../types.js').Decision[]}
 */
function filterIpListScopes(decisions) {
	return decisions.filter((d) => IP_LIST_SCOPES.includes(d.scope));
}

/**
 * Convert decisions into queue-upsert entries. Skips new decisions for IPs
 * already present in a managed list (nothing to do; sticky by construction
 * since we never move an IP once it's placed) — expired decisions are never
 * skipped this way, since they need to reach the queue even if the IP isn't
 * currently in any list (e.g. it was queued as 'new' but never pushed yet).
 * @param {import('../types.js').Decision[]} decisions
 * @param {Map<string, Map<string, {itemId: string, action: string, until: string}>>} index
 * @param {boolean} isExpiry
 * @returns {{ip: string, action: string, until: string}[]}
 */
function planQueueUpserts(decisions, index, isExpiry) {
	const alreadyInLists = new Set();
	if (!isExpiry) {
		for (const members of index.values()) {
			for (const ip of members.keys()) alreadyInLists.add(ip);
		}
	}

	const toUpsert = [];
	for (const decision of filterIpListScopes(decisions)) {
		if (!isExpiry && alreadyInLists.has(decision.value)) continue;
		toUpsert.push({ ip: decision.value, action: decision.type, until: decision.until });
	}
	return toUpsert;
}

/**
 * Split a batch of queue rows (mixed 'new'/'delete') into a delete plan
 * (grouped by the list currently holding each IP, for one DELETE call per
 * affected list) and the subset of rows that are actually new additions to
 * plan placement for.
 * @param {{ip: string, action: string, until: string, listAction: string}[]} batch
 * @param {Map<string, Map<string, {itemId: string, action: string, until: string}>>} index
 * @returns {{deletesByList: Map<string, {ip: string, itemId: string}[]>, notFoundDeletes: string[], newRows: {ip: string, action: string, until: string}[]}}
 */
function splitBatch(batch, index) {
	const deletesByList = new Map();
	const notFoundDeletes = [];
	const newRows = [];

	for (const row of batch) {
		if (row.listAction === 'new') {
			newRows.push({ ip: row.ip, action: row.action, until: row.until });
			continue;
		}

		// row.listAction === 'delete'
		let hit = null;
		for (const [listName, members] of index) {
			const entry = members.get(row.ip);
			if (entry) {
				hit = { listName, itemId: entry.itemId };
				break;
			}
		}

		if (!hit) {
			// Was queued as 'new' but never actually pushed to a list before
			// expiring — nothing on Cloudflare to remove, just a queue row to drop.
			notFoundDeletes.push(row.ip);
			continue;
		}

		if (!deletesByList.has(hit.listName)) {
			deletesByList.set(hit.listName, []);
		}
		deletesByList.get(hit.listName).push({ ip: row.ip, itemId: hit.itemId });
	}

	return { deletesByList, notFoundDeletes, newRows };
}

/**
 * Pack a batch of new queue rows into managed lists in order: list 1 is
 * filled to MAX_ITEMS_PER_LIST before list 2 is touched, etc. A list already
 * at capacity is skipped entirely. Items that don't fit anywhere are left
 * un-planned (still in the queue, retried next tick).
 * @param {{ip: string, action: string, until: string}[]} newRows
 * @param {string[]} listNames - managed list names, in stable (sorted) order
 * @param {Map<string, Map<string, {itemId: string, action: string, until: string}>>} index
 * @returns {{addsByList: Map<string, {ip: string, action: string, until: string}[]>, unplaced: string[]}}
 */
function planAdds(newRows, listNames, index) {
	const sizeByList = new Map(listNames.map((name) => [name, index.get(name)?.size ?? 0]));
	const addsByList = new Map();
	const unplaced = [];

	for (const item of newRows) {
		let target = null;
		for (const listName of listNames) {
			if (sizeByList.get(listName) < MAX_ITEMS_PER_LIST) {
				target = listName;
				break;
			}
		}

		if (!target) {
			unplaced.push(item.ip);
			continue;
		}

		sizeByList.set(target, sizeByList.get(target) + 1);
		if (!addsByList.has(target)) addsByList.set(target, []);
		addsByList.get(target).push(item);
	}

	return { addsByList, unplaced };
}

;// ./src/index.js
/**
 * CrowdSec Autonomous Decisions Sync Worker
 * Periodically fetches security decisions from CrowdSec LAPI and updates Cloudflare KV (CROWDSECCFBOUNCERNS) storage
 */








const DEFAULT_IP_LIST_PREFIX = 'crowdsec_';
const DEFAULT_IP_LIST_BATCH_SIZE = 1000;

/**
 * Sync decisions to the Worker's KV store (used by the L7 bouncer worker).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @param {boolean} isFirst
 */
async function syncToKv(env, decisions, isFirst) {
	logger.info('Starting KV sync...');

	// Step 1: Get existing IP_RANGES from KV
	const existingRanges = await getIpRanges(env.CROWDSECCFBOUNCERNS);

	// Step 2: Check existing string decisions in KV (only on incremental updates, not first run)
	let existingStringDecisions = new Map();

	if (!isFirst) {
		// On incremental updates, check existing values to avoid redundant writes
		logger.debug('Incremental update: checking existing decisions in KV');
		const allStringKeys = [
			...decisions.new
				.filter((d) => ['ip', 'as', 'country'].includes(d.scope))
				.map((d) => (d.scope === 'country' ? d.value.toLowerCase() : d.value)),
			...decisions.deleted
				.filter((d) => ['ip', 'as', 'country'].includes(d.scope))
				.map((d) => (d.scope === 'country' ? d.value.toLowerCase() : d.value)),
		];

		// Remove duplicates
		const uniqueStringKeys = [...new Set(allStringKeys)];

		// Fetch existing string decisions from KV using bulk API
		existingStringDecisions = await batchGetStringBasedDecisions(
			env.CF_ACCOUNT_ID,
			env.CF_KV_NAMESPACE_ID,
			env.CF_API_TOKEN,
			uniqueStringKeys
		);
	} else {
		logger.debug('First run: skipping existence check (KV is empty)');
	}

	// Step 3: Process new decisions
	const newProcessed = processNewDecisions(decisions.new, existingStringDecisions, existingRanges);
	// Step 4: Process deleted decisions
	const deletedProcessed = processDeletedDecisions(decisions.deleted, existingStringDecisions, existingRanges);
	// Step 5: Merge ranges (deletions already applied in step 4, now adding new ranges)
	const finalRanges = mergeRanges(deletedProcessed.updatedRanges, newProcessed.jsonEntries);
	// Step 6: Write new/updated string decisions (IP, AS, Country) to KV using bulk API
	if (newProcessed.stringEntries.length > 0) {
		logger.info('Writing string-based decisions to KV...', { count: newProcessed.stringEntries.length });
		await batchWriteStringBasedDecisions(env.CF_ACCOUNT_ID, env.CF_KV_NAMESPACE_ID, env.CF_API_TOKEN, newProcessed.stringEntries);
	}
	// Step 7: Delete string decisions from KV using bulk API
	if (deletedProcessed.stringKeysToDelete.length > 0) {
		logger.info('Deleting string decisions from KV...', { count: deletedProcessed.stringKeysToDelete.length });
		await batchDeleteStringBasedDecisions(
			env.CF_ACCOUNT_ID,
			env.CF_KV_NAMESPACE_ID,
			env.CF_API_TOKEN,
			deletedProcessed.stringKeysToDelete
		);
	}
	// Step 8: Update IP_RANGES if changed
	if (hasRangesChanged(existingRanges, finalRanges)) {
		logger.info('IP_RANGES changed, updating KV...');
		await writeIpRanges(env.CROWDSECCFBOUNCERNS, finalRanges);
	}

	logger.info('KV sync completed successfully', {
		stringWritten: newProcessed.stringEntries.length,
		stringDeleted: deletedProcessed.stringKeysToDelete.length,
		rangesCount: Object.keys(finalRanges).length,
	});
}

/**
 * Sync decisions to Cloudflare IP Lists (used for L3/4 bouncing). List
 * creation and the firewall rules referencing these lists are provisioned
 * externally — this only fills/empties membership of lists whose name
 * starts with IP_LIST_PREFIX.
 *
 * Decisions are queued in a D1 table (env.CROWDSECCFBOUNCER_QUEUE_DB) rather
 * than applied immediately: each tick upserts new/expired decisions into the
 * queue, reads back a bounded batch (IP_LIST_BATCH_SIZE rows, a mix of
 * pending adds and removals), applies it to Cloudflare, and only then
 * deletes those rows from the queue. This makes a large warmup (which can
 * take days at realistic decision volumes) resumable — a rate limit or
 * error mid-tick just leaves the rest queued for next time — and an
 * append-only add / id-targeted remove never overwrites IPs some other
 * process added to the same lists, unlike a full-replace would.
 *
 * On the first sync after a cold start, the caller clears both the queue and
 * the managed lists (clearAllIpLists) before this runs, so what's upserted
 * here is a clean full-state pull rather than layered on residue from a
 * previously interrupted warmup. Draining the queue toward Cloudflare is a
 * separate, ongoing process that continues across ticks regardless of
 * isFirst — WARMED_UP only means "the initial full pull from LAPI has been
 * captured into the queue", not "the queue is empty".
 *
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>} true unless this tick stopped early (rate
 *   limit or error) — an unplaced/still-queued remainder is normal, expected
 *   progress, not a failure.
 */
async function syncToIpLists(env, decisions) {
	logger.info('Starting IP list sync...');

	const backoffUntil = await getBackoffUntil(env.CROWDSECCFBOUNCERNS);
	if (backoffUntil && backoffUntil > new Date()) {
		logger.warn('Skipping IP list sync: backing off after a previous rate limit', {
			backoffUntil: backoffUntil.toISOString(),
		});
		return false;
	}

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const batchSize = env.IP_LIST_BATCH_SIZE ? parseInt(env.IP_LIST_BATCH_SIZE, 10) : DEFAULT_IP_LIST_BATCH_SIZE;
	const db = env.CROWDSECCFBOUNCER_QUEUE_DB;

	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	if (lists.length === 0) {
		logger.warn(`No IP Lists found with prefix "${prefix}"; skipping IP list sync`);
		// Nothing we can do without any managed lists; don't block warming on it.
		return true;
	}

	const listNames = lists.map((l) => l.name);
	const listById = new Map(lists.map((l) => [l.name, l.id]));
	const index = await readIndex(env.CROWDSECCFBOUNCERNS, lists);

	// --- upsert expired decisions into the queue as 'delete' rows ---
	const toDeleteRows = planQueueUpserts(decisions.deleted, index, /* isExpiry */ true);
	await upsertQueue(db, toDeleteRows, 'delete');

	// --- upsert new decisions into the queue as 'new' rows ---
	const toNewRows = planQueueUpserts(decisions.new, index, /* isExpiry */ false);
	await upsertQueue(db, toNewRows, 'new');

	// --- read a bounded batch back (mix of pending adds/removals) ---
	const batch = await readQueueBatch(db, batchSize);
	if (batch.length === 0) {
		logger.info('IP list sync completed successfully (queue empty)');
		await clearBackoff(env.CROWDSECCFBOUNCERNS);
		return true;
	}

	const { deletesByList, notFoundDeletes, newRows } = splitBatch(batch, index);
	const { addsByList, unplaced } = planAdds(newRows, listNames, index);
	if (unplaced.length > 0) {
		logger.warn(`${unplaced.length} queued IP(s) have no room in any managed list; left queued`);
	}

	const confirmedIps = new Set(notFoundDeletes); // nothing to remove from Cloudflare; just drop the queue row
	let removedCount = 0;
	let addedCount = 0;
	// Per-list tallies for the completion summary below, so it's clear at a
	// glance which lists were actually touched this tick and by how much.
	const updatedLists = new Map(); // listName -> { added, removed }
	const bumpListStat = (listName, key, n) => {
		const stat = updatedLists.get(listName) || { added: 0, removed: 0 };
		stat[key] += n;
		updatedLists.set(listName, stat);
	};

	for (const [listName, toDelete] of deletesByList) {
		const listId = listById.get(listName);
		logger.info(`Removing ${toDelete.length} item(s) from IP list ${listName}...`, {
			list: listName,
			removed: toDelete.length,
		});
		try {
			await removeListItems(
				env.CF_ACCOUNT_ID,
				env.CF_API_TOKEN,
				listId,
				toDelete.map((t) => t.itemId)
			);
		} catch (e) {
			await deleteQueueRows(db, [...confirmedIps]);
			return handleIpListError(env, e, `removing items from IP list ${listName}`);
		}
		const members = index.get(listName);
		for (const { ip } of toDelete) {
			members.delete(ip);
			confirmedIps.add(ip);
			removedCount++;
		}
		bumpListStat(listName, 'removed', toDelete.length);
		await writeIndexShard(env.CROWDSECCFBOUNCERNS, listName, members);
	}

	for (const [listName, items] of addsByList) {
		const listId = listById.get(listName);
		const ips = items.map((i) => i.ip);
		logger.info(`Adding ${ips.length} item(s) to IP list ${listName}...`, {
			list: listName,
			added: ips.length,
		});

		let itemIdByIp;
		try {
			itemIdByIp = await addListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, listId, ips);
		} catch (e) {
			// Whatever was already applied and persisted in earlier iterations of
			// these loops stays applied; the rest of the batch stays queued.
			await deleteQueueRows(db, [...confirmedIps]);
			return handleIpListError(env, e, `adding items to IP list ${listName}`);
		}

		const members = index.get(listName);
		let listAddedCount = 0;
		for (const item of items) {
			const itemId = itemIdByIp.get(item.ip);
			if (!itemId) continue; // resolution failure already logged by addListItems
			members.set(item.ip, { itemId, action: item.action, until: item.until });
			confirmedIps.add(item.ip);
			addedCount++;
			listAddedCount++;
		}
		bumpListStat(listName, 'added', listAddedCount);
		await writeIndexShard(env.CROWDSECCFBOUNCERNS, listName, members);
	}

	// Only rows Cloudflare actually confirmed leave the queue; unplaced adds
	// stay put for a future tick.
	await deleteQueueRows(db, [...confirmedIps]);

	// Made it through this tick without hitting a rate limit; clear any
	// stale backoff from a previous run so the next tick isn't held back
	// unnecessarily.
	await clearBackoff(env.CROWDSECCFBOUNCERNS);

	logger.info('IP list sync completed successfully', {
		removed: removedCount,
		added: addedCount,
		listsUpdated: [...updatedLists.entries()].map(([list, stat]) => ({ list, ...stat })),
		unplaced: unplaced.length,
		batchSize: batch.length,
	});

	return true;
}

/**
 * Shared handling for a failed IP list mutation: distinguish a rate limit
 * (which we can back off for a known duration) from anything else (which we
 * can't reliably identify, so we just stop and retry next tick).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {unknown} e
 * @param {string} what - human-readable description of the failed operation
 * @returns {Promise<false>}
 */
async function handleIpListError(env, e, what) {
	if (e instanceof CloudflareApiError && e.status === 429 && e.retryAfterSeconds !== undefined) {
		logger.warn(`Rate limited ${what}; backing off`, { retryAfterSeconds: e.retryAfterSeconds });
		await setBackoff(env.CROWDSECCFBOUNCERNS, e.retryAfterSeconds);
	} else {
		// Anything else (quota exceeded, malformed request, transient 5xx,
		// ...) — Cloudflare doesn't give us a reliable way to tell these apart
		// from the response alone, so stop for this run and retry next sync
		// rather than risk cascading failures.
		logger.error(`Failed ${what}; stopping IP list sync for this run`, {
			error: e instanceof Error ? e.message : String(e),
			status: e instanceof CloudflareApiError ? e.status : undefined,
			body: e instanceof CloudflareApiError ? e.body : undefined,
		});
	}
	return false;
}

/**
 * Empty every managed IP list and the pending queue. Used when LAPI reports
 * no decisions at all (HTTP 204), mirroring the KV path's resetAllDecisions.
 * @param {import('./types.js').CrowdSecEnv} env
 */
async function clearAllIpLists(env) {
	logger.info('Clearing all managed IP lists...');

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	const index = await readIndex(env.CROWDSECCFBOUNCERNS, lists);

	const clearedLists = [];
	for (const list of lists) {
		const members = index.get(list.name);
		if (members.size === 0) continue;

		logger.info(`Emptying IP list ${list.name}...`, { list: list.name, removed: members.size });
		await removeListItems(
			env.CF_ACCOUNT_ID,
			env.CF_API_TOKEN,
			list.id,
			[...members.values()].map((entry) => entry.itemId)
		);
		await writeIndexShard(env.CROWDSECCFBOUNCERNS, list.name, new Map());
		clearedLists.push({ list: list.name, removed: members.size });
	}

	await clearQueue(env.CROWDSECCFBOUNCER_QUEUE_DB);

	logger.info('All managed IP lists cleared successfully', { listCount: lists.length, listsUpdated: clearedLists });
}

/* harmony default export */ const src = ({
	/**
	 * Scheduled handler
	 * @param {ScheduledEvent} event - The scheduled event
	 * @param {import('./types.js').CrowdSecEnv} env - Environment bindings (secrets, KV namespaces, etc.)
	 * @param {ExecutionContext} _ctx - Execution context
	 */
	async scheduled(event, env, _ctx) {
		const startTime = Date.now();

		logger.info('Decision sync started', { cron: event.cron, scheduledTime: event.scheduledTime });

		try {
			// Both sync targets default to their historical behavior: KV sync
			// (the L7 bouncer worker's data source) is on unless explicitly
			// disabled; IP list sync (L3/4 firewall rules) is off unless opted in.
			const syncToKvEnabled = env.SYNC_TO_KV !== 'false';
			const syncToIpListsEnabled = env.SYNC_TO_IP_LISTS === 'true';

			if (!syncToKvEnabled && !syncToIpListsEnabled) {
				logger.error('Both SYNC_TO_KV and SYNC_TO_IP_LISTS are disabled; nothing to do');
				return;
			}

			// Validate required environment variables
			if (!env.LAPI_URL) {
				logger.error('LAPI_URL environment variable is not set');
				return;
			}

			if (!env.LAPI_KEY) {
				logger.error('LAPI_KEY secret is not set');
				return;
			}

			// CROWDSECCFBOUNCERNS is required in both modes: it's the L7 worker's
			// data store in KV mode, and it also holds the sync lock, warmed
			// flag, reset flag, and the IP list membership index in list mode.
			if (!env.CROWDSECCFBOUNCERNS) {
				logger.error('CROWDSECCFBOUNCERNS KV namespace is not bound');
				return;
			}

			if (!env.CF_ACCOUNT_ID) {
				logger.error('CF_ACCOUNT_ID environment variable is not set');
				return;
			}

			if (syncToKvEnabled && !env.CF_KV_NAMESPACE_ID) {
				logger.error('CF_KV_NAMESPACE_ID environment variable is not set (required when SYNC_TO_KV is enabled)');
				return;
			}

			if (syncToIpListsEnabled && !env.CROWDSECCFBOUNCER_QUEUE_DB) {
				logger.error('CROWDSECCFBOUNCER_QUEUE_DB D1 database is not bound (required when SYNC_TO_IP_LISTS is enabled)');
				return;
			}

			if (!env.CF_API_TOKEN) {
				logger.error('CF_API_TOKEN secret is not set (required for bulk KV/IP list operations)');
				return;
			}

			const lapiUrl = env.LAPI_URL.replace(/\/$/, ''); // Remove trailing slash if present

			// Acquire the sync lock so an overlapping cron tick (or a manual run
			// while a previous one is still in flight) doesn't fan out into a
			// full-sync storm against LAPI. Released in finally below; TTL is
			// only a backstop for a hard crash.
			const lockAcquired = await tryAcquireSyncLock(env.CROWDSECCFBOUNCERNS);
			if (!lockAcquired) {
				logger.info('Sync already in progress, skipping this run');
				return;
			}

			try {
				// Determine if this is the first fetch
				const isFirst = await isFirstFetch(env.CROWDSECCFBOUNCERNS);
				logger.info('Fetch type determined', { isFirstFetch: isFirst });

				// Check if reset is requested
				const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);

				// Clear residual state before the pull, both on an explicit RESET
				// and on the very first sync after a cold start — either way,
				// what's about to be fetched from LAPI (startup=true below) is the
				// full current state, not a diff, so stale entries from a previous
				// run (KV keys, D1 queue rows, IP list membership) must not survive
				// into it.
				if ((resetRequested || isFirst) && syncToKvEnabled) {
					logger.info('Clearing all decision keys from KV before fresh sync...');
					await resetAllDecisions(
						env.CF_ACCOUNT_ID,
						env.CF_KV_NAMESPACE_ID,
						env.CF_API_TOKEN,
						env.CROWDSECCFBOUNCERNS
					);
				}
				if ((resetRequested || isFirst) && syncToIpListsEnabled) {
					logger.info('Clearing all managed IP lists and the sync queue before fresh sync...');
					await clearAllIpLists(env);
				}
				if (resetRequested && !syncToKvEnabled) {
					// resetAllDecisions (above) already clears RESET as part of
					// wiping KV; in IP-list-only mode it's never called, so clear
					// the flag here or a manual RESET=true would never be
					// acknowledged and would keep re-triggering every tick.
					await clearResetFlag(env.CROWDSECCFBOUNCERNS);
				}

				// Parse optional filter configuration
				const scenariosContaining = env.INCLUDE_SCENARIOS ? env.INCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
				const scenariosNotContaining = env.EXCLUDE_SCENARIOS ? env.EXCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
				const origins = env.ONLY_INCLUDE_ORIGINS ? env.ONLY_INCLUDE_ORIGINS.split(',').map((s) => s.trim()) : [];

				// Fetch decisions from LAPI
				const decisions = await fetchDecisionsStream(lapiUrl, env.LAPI_KEY, {
					startup: isFirst,
					scenariosContaining,
					scenariosNotContaining,
					origins,
				});

				// Log summary
				const duration = ((Date.now() - startTime) / 1000).toFixed(2);
				logger.info('Decision stream completed successfully', {
					duration: `${duration}s`,
					newDecisions: decisions.new.length,
					deletedDecisions: decisions.deleted.length,
				});

				// Handle HTTP 204 (LAPI has no decisions - delete all from KV)
				if (decisions.deleteAll) {
					if (syncToKvEnabled) {
						logger.info('LAPI has no decisions (204): clearing all decision keys from KV...');
						await resetAllDecisions(
							env.CF_ACCOUNT_ID,
							env.CF_KV_NAMESPACE_ID,
							env.CF_API_TOKEN,
							env.CROWDSECCFBOUNCERNS
						);
					}
					if (syncToIpListsEnabled) {
						await clearAllIpLists(env);
					}
					// Safe to mark warmed here: KV is now in its intended empty state,
					// so a crash at this point doesn't leave decisions unwritten.
					if (isFirst) {
						await markAsWarmed(env.CROWDSECCFBOUNCERNS);
						logger.info('Cache marked as warmed (LAPI has no decisions)');
					}
					const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
					logger.info('Cleared successfully (LAPI has no decisions)', {
						totalDuration: `${finalDuration}s`,
					});
					return; // Exit early - no further sync needed
				}

				if (syncToKvEnabled) {
					// Throws on failure, so reaching the next line means it fully completed.
					await syncToKv(env, decisions, isFirst);
				}

				// syncToIpLists upserts the full incoming batch into the D1 queue
				// before attempting any Cloudflare push, so WARMED_UP (meaning "the
				// initial full pull from LAPI has been captured") is correct even if
				// the push itself is rate-limited or fails — that failure only
				// delays draining the queue toward Cloudflare, a separate ongoing
				// process independent of isFirst. Only treat it as blocking warmup
				// if it fails outright (returns false).
				let ipListsSucceeded = true;
				if (syncToIpListsEnabled) {
					ipListsSucceeded = await syncToIpLists(env, decisions);
				}

				// Mark cache as warmed ONLY after all enabled sync targets have
				// captured this run's decisions. If this runs before every write
				// actually landed, a mid-sync crash leaves WARMED_UP=true with some
				// decisions never applied, and the next run does an incremental
				// fetch that never backfills what was missed — a silent
				// enforcement gap.
				if (isFirst && ipListsSucceeded) {
					await markAsWarmed(env.CROWDSECCFBOUNCERNS);
					logger.info('Cache marked as warmed (first sync complete)');
				} else if (isFirst) {
					logger.warn('First sync incomplete (IP list sync failed); cache not marked as warmed yet');
				}

				// Final summary
				const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
				logger.info('Decision sync completed successfully', { totalDuration: `${finalDuration}s` });
			} finally {
				await releaseSyncLock(env.CROWDSECCFBOUNCERNS);
			}
		} catch (error) {
			const duration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.error('Decision sync failed', {
				duration: `${duration}s`,
				error: error.message,
				stack: error.stack,
			});

			// Don't throw - we want to continue running on the next cron trigger
			// The existing decisions in KV (if any) will remain valid
		}
	},
});

export { src as default };
