
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
 * Check if the cache needs to be warmed up by looking for the WARMED_UP flag in KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<boolean>} True if the cache needs to be warmed up (WARMED_UP is not exactly 'true')
 */
async function needWarmUp(kvNamespace) {
	const warmedUpFlag = await kvNamespace.get(WARMED_UP_KEY);
	return warmedUpFlag !== 'true';
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
 * Clear the RESET state in KV
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

	logger.info('KV reset completed successfully');
}

;// ./src/core/ip-list-processor.js
/**
 * IP List Processor
 * Pure planning logic for the D1-backed Cloudflare IP List sync (L3/4
 * bouncing). Only 'ip' and 'range' scoped decisions apply here — country/AS
 * decisions aren't representable in a Cloudflare IP List.
 *
 * The D1 table (ip_list_state) is the single source of truth for both
 * pending work and current membership, so planning here only ever deals
 * with plain decision objects and plain row objects — no separate
 * in-memory index to keep in sync with it.
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
 * Split new/deleted decisions into upsert-ready entries, resolving the case
 * where the same IP appears in both batches from the same LAPI pull. That's
 * an unusual signal (a decision both freshly issued and freshly expired at
 * once) — logged so it can be traced back to LAPI's stream — but delete
 * always wins: the two batches below are upserted in order (news, then
 * deletes; see upsertNews/upsertDeletes), so the delete overwrites whatever
 * the new-decision upsert would otherwise have set.
 * @param {import('../types.js').Decision[]} newDecisions
 * @param {import('../types.js').Decision[]} expiredDecisions
 * @param {(msg: string, ctx?: object) => void} warn - logger.warn, injected so this stays a pure function
 * @returns {{newItems: {ip: string, action: string, until: string}[], deleteItems: {ip: string, action: string, until: string}[]}}
 */
function planUpserts(newDecisions, expiredDecisions, warn) {
	const newScoped = filterIpListScopes(newDecisions);
	const deleteScoped = filterIpListScopes(expiredDecisions);

	const deleteIps = new Set(deleteScoped.map((d) => d.value));
	const conflicting = newScoped.filter((d) => deleteIps.has(d.value)).map((d) => d.value);
	if (conflicting.length > 0) {
		warn(`${conflicting.length} IP(s) appear in both new and expired decisions this tick; delete wins`, {
			ips: conflicting,
		});
	}

	const toEntry = (d) => ({ ip: d.value, action: d.type, until: d.until });
	return {
		newItems: newScoped.map(toEntry),
		deleteItems: deleteScoped.map(toEntry),
	};
}

/**
 * Pack a batch of pending-add rows into managed lists in order: list 1 is
 * filled to MAX_ITEMS_PER_LIST before list 2 is touched, etc, based on
 * current member counts (readListSizes). A list already at capacity is
 * skipped entirely. Items that don't fit anywhere are left un-planned
 * (still 'new' in the queue, retried next tick).
 * @param {{ip: string, action: string, until: string}[]} pendingAdds
 * @param {string[]} listIds - managed list ids, in stable (name-sorted) order
 * @param {Map<string, number>} listSizes - list_id -> current member count
 * @param {number} maxItemsPerList
 * @returns {{addsByList: Map<string, {ip: string, action: string, until: string}[]>, unplaced: string[]}}
 */
function planAdds(pendingAdds, listIds, listSizes, maxItemsPerList) {
	const sizeByList = new Map(listIds.map((id) => [id, listSizes.get(id) ?? 0]));
	const addsByList = new Map();
	const unplaced = [];

	for (const item of pendingAdds) {
		let target = null;
		for (const listId of listIds) {
			if (sizeByList.get(listId) < maxItemsPerList) {
				target = listId;
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

;// ./src/adapters/cloudflare-ip-lists.js
/**
 * Cloudflare IP Lists Adapter
 * Manages membership of CrowdSec-prefixed IP Lists for L3/4 (firewall rule)
 * bouncing. List creation and the firewall rules that reference these lists
 * are provisioned by an external process — this adapter only fills/empties
 * list membership.
 *
 * A single D1 table (ip_list_state) is the source of truth for both pending
 * work and current membership — see the D1_* functions below. Each row's
 * list_action is one of:
 *   'new'    - pending add, not yet pushed to any Cloudflare list
 *   'delete' - pending removal from list_id/item_id
 *   'listed' - currently a member of list_id (item_id is Cloudflare's id for
 *              it there); nothing pending
 * There is no separate index: list_id/item_id live on the row itself, so
 * finding which list holds an IP — or how full a list currently is — is a
 * plain query against this one table instead of a second KV-backed store.
 *
 * New/expired decisions are queued (list_action='new'/'delete') rather than
 * applied to Cloudflare immediately: each sync tick processes pending
 * deletes and adds against a bounded slice of the table. This lets warmup
 * (which can take days at realistic decision volumes) make steady, resumable
 * progress without ever overwriting IPs some other process added to the same
 * lists — an append-only add and an id-targeted remove never touch anything
 * outside what this worker itself is tracking.
 */



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
// until, list_action) for a 'new'/'delete' upsert, so 25 rows is the most
// that fit in one multi-row VALUES statement.
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
 * Upsert expired decisions into the queue, unconditionally forcing
 * list_action='delete' — even for a row that was already 'listed', since
 * that's exactly the row we want removed.
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 */
async function upsertDeletes(db, items) {
	if (items.length === 0) return;

	const chunks = chunk(items, D1_MAX_ROWS_PER_STATEMENT);
	const statements = chunks.map((rows) => {
		const placeholders = rows.map(() => '(?, ?, ?, ?)').join(', ');
		const params = rows.flatMap((item) => [item.ip, item.action, item.until ?? null, 'delete']);
		return db
			.prepare(
				`INSERT INTO ip_list_state (ip, action, until, list_action) VALUES ${placeholders}
				 ON CONFLICT(ip) DO UPDATE SET action = excluded.action, until = excluded.until, list_action = 'delete'`
			)
			.bind(...params);
	});

	await db.batch(statements);
}

/**
 * Upsert new decisions into the queue as list_action='new' — unless the row
 * is already 'listed', in which case list_action is left untouched (only
 * action/until refresh). Without this guard, a decision CrowdSec re-sends
 * for an IP that's already placed would flip it back to 'new' and lose its
 * list_id/item_id, causing it to be (redundantly, harmlessly, but wastefully)
 * re-added on a future tick.
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 */
async function upsertNews(db, items) {
	if (items.length === 0) return;

	const chunks = chunk(items, D1_MAX_ROWS_PER_STATEMENT);
	const statements = chunks.map((rows) => {
		const placeholders = rows.map(() => '(?, ?, ?, ?)').join(', ');
		const params = rows.flatMap((item) => [item.ip, item.action, item.until ?? null, 'new']);
		return db
			.prepare(
				`INSERT INTO ip_list_state (ip, action, until, list_action) VALUES ${placeholders}
				 ON CONFLICT(ip) DO UPDATE SET
				   action = excluded.action,
				   until = excluded.until,
				   list_action = CASE WHEN ip_list_state.list_action != 'listed' THEN excluded.list_action ELSE ip_list_state.list_action END`
			)
			.bind(...params);
	});

	await db.batch(statements);
}

/**
 * Read every row pending deletion, grouped by the list it's currently in.
 * A row with no list_id (queued 'new' then expired before ever being
 * pushed) has nothing on Cloudflare to remove — it's returned separately so
 * the caller can just drop it from the queue.
 * @param {D1Database} db
 * @returns {Promise<{deletesByList: Map<string, {ip: string, itemId: string}[]>, queueOnlyDeletes: string[]}>}
 */
async function readPendingDeletes(db) {
	const result = await db.prepare("SELECT ip, list_id, item_id FROM ip_list_state WHERE list_action = 'delete'").all();

	const deletesByList = new Map();
	const queueOnlyDeletes = [];

	for (const row of result.results || []) {
		if (!row.list_id || !row.item_id) {
			queueOnlyDeletes.push(row.ip);
			continue;
		}
		if (!deletesByList.has(row.list_id)) {
			deletesByList.set(row.list_id, []);
		}
		deletesByList.get(row.list_id).push({ ip: row.ip, itemId: row.item_id });
	}

	return { deletesByList, queueOnlyDeletes };
}

/**
 * Read every row currently marked 'listed', grouped by list. Used only by
 * clearAllIpLists (warmup/reset/204) to empty every managed list wholesale —
 * the normal per-tick flow never needs "all listed rows" in one shot.
 * @param {D1Database} db
 * @returns {Promise<Map<string, {ip: string, itemId: string}[]>>} list_id -> members
 */
async function readAllListed(db) {
	const result = await db.prepare("SELECT ip, list_id, item_id FROM ip_list_state WHERE list_action = 'listed'").all();

	const byList = new Map();
	for (const row of result.results || []) {
		if (!byList.has(row.list_id)) {
			byList.set(row.list_id, []);
		}
		byList.get(row.list_id).push({ ip: row.ip, itemId: row.item_id });
	}
	return byList;
}

/**
 * Remove a batch of rows entirely (used once their deletion — or lack of
 * anything to delete — has been confirmed).
 * @param {D1Database} db
 * @param {string[]} ips
 */
async function deleteQueueRows(db, ips) {
	if (ips.length === 0) return;

	// Each bound ip is 1 param, so up to 100 fit in one IN (...) statement.
	const chunks = chunk(ips, 100);
	const statements = chunks.map((rows) => {
		const placeholders = rows.map(() => '?').join(', ');
		return db.prepare(`DELETE FROM ip_list_state WHERE ip IN (${placeholders})`).bind(...rows);
	});

	await db.batch(statements);
}

/**
 * Read up to `limit` rows still pending an add (list_action='new').
 * @param {D1Database} db
 * @param {number} limit
 * @returns {Promise<{ip: string, action: string, until: string}[]>}
 */
async function readPendingAdds(db, limit) {
	const result = await db
		.prepare("SELECT ip, action, until FROM ip_list_state WHERE list_action = 'new' LIMIT ?")
		.bind(limit)
		.all();
	return result.results || [];
}

/**
 * Current member count per managed list, from the rows already marked
 * 'listed' — the actual source of truth for how much room is left,
 * queried fresh each tick rather than tracked separately.
 * @param {D1Database} db
 * @returns {Promise<Map<string, number>>} list_id -> count
 */
async function readListSizes(db) {
	const result = await db.prepare("SELECT list_id, COUNT(*) as n FROM ip_list_state WHERE list_action = 'listed' GROUP BY list_id").all();
	const sizes = new Map();
	for (const row of result.results || []) {
		sizes.set(row.list_id, row.n);
	}
	return sizes;
}

/**
 * Mark a batch of rows as confirmed members of a list, once Cloudflare has
 * accepted the add.
 * @param {D1Database} db
 * @param {string} listId
 * @param {{ip: string, itemId: string}[]} placed
 */
async function markListed(db, listId, placed) {
	if (placed.length === 0) return;

	const stmt = db.prepare("UPDATE ip_list_state SET list_action = 'listed', list_id = ?, item_id = ? WHERE ip = ?");
	await db.batch(placed.map((p) => stmt.bind(listId, p.itemId, p.ip)));
}

/**
 * Delete every row from the D1 queue table. Used when LAPI reports no
 * decisions at all (HTTP 204), or on the first sync after a cold start,
 * mirroring the KV path's resetAllDecisions.
 * @param {D1Database} db
 */
async function clearQueue(db) {
	await db.prepare('DELETE FROM ip_list_state').run();
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



;// ./src/index.js
/**
 * CrowdSec Autonomous Decisions Sync Worker
 * Periodically fetches security decisions from CrowdSec LAPI and updates
 * exactly one sync target: Cloudflare KV (SYNC_TO_LIST_NOT_KV=false, the
 * default) or Cloudflare IP Lists (SYNC_TO_LIST_NOT_KV=true).
 */








const DEFAULT_IP_LIST_PREFIX = 'crowdsec_';
const DEFAULT_IP_LIST_BATCH_SIZE = 1000;

/**
 * Scheduled handler
 * @param {ScheduledEvent} event - The scheduled event
 * @param {import('./types.js').CrowdSecEnv} env - Environment bindings (secrets, KV namespaces, etc.)
 * @param {ExecutionContext} _ctx - Execution context
 */
async function scheduled(event, env, _ctx) {
	const startTime = Date.now();

	logger.info('Decision sync started', { cron: event.cron, scheduledTime: event.scheduledTime });

	try {
		// The worker always syncs to exactly one target, never both — this
		// keeps warmup/WARMED_UP handling simple, since there's only ever one
		// sync target's completion to wait on. Any value other than the
		// literal string "true" means KV mode (the default).
		const syncToListsMode = env.SYNC_TO_LIST_NOT_KV === 'true';
		const syncToKvEnabled = !syncToListsMode;
		const syncToIpListsEnabled = syncToListsMode;

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
		// flag, reset flag, and IP-list backoff timer in list mode.
		if (!env.CROWDSECCFBOUNCERNS) {
			logger.error('CROWDSECCFBOUNCERNS KV namespace is not bound');
			return;
		}

		if (!env.CF_ACCOUNT_ID) {
			logger.error('CF_ACCOUNT_ID environment variable is not set');
			return;
		}

		// CF_KV_NAMESPACE_ID is only used for bulk KV API calls
		if (syncToKvEnabled && !env.CF_KV_NAMESPACE_ID) {
			logger.error('CF_KV_NAMESPACE_ID environment variable is not set (required when syncing to KV)');
			return;
		}

		if (syncToIpListsEnabled && !env.LIST_STATE_DB) {
			logger.error('LIST_STATE_DB D1 database is not bound (required when syncing to IP Lists)');
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
			const needStartUpFetch = await needWarmUp(env.CROWDSECCFBOUNCERNS);
			logger.info('Fetch type determined', { startup: needStartUpFetch });

			// Check if reset is requested
			const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);

			// Clear residual state before the pull, both on an explicit RESET
			// and on the very first sync after a cold start — either way,
			// what's about to be fetched from LAPI (startup=true below) is the
			// full current state, not a diff, so stale entries from a previous
			// run must not survive into it.
			if ((resetRequested || needStartUpFetch) && syncToKvEnabled) {
				logger.info('Clearing all decision keys from KV before fresh sync...');
				await resetAllDecisions(
					env.CF_ACCOUNT_ID,
					env.CF_KV_NAMESPACE_ID,
					env.CF_API_TOKEN,
					env.CROWDSECCFBOUNCERNS
				);
			}
			if ((resetRequested || needStartUpFetch) && syncToIpListsEnabled) {
				logger.info('Clearing all managed IP lists and the sync queue before fresh sync...');
				await clearAllIpLists(env);
			}
			if (resetRequested && syncToIpListsEnabled) {
				// resetAllDecisions (above) already clears RESET as part of
				// wiping KV; in IP-list mode it's never called, so clear the
				// flag here or a manual RESET=true would never be acknowledged
				// and would keep re-triggering every tick.
				await clearResetFlag(env.CROWDSECCFBOUNCERNS);
			}

			// Parse optional filter configuration
			const scenariosContaining = env.INCLUDE_SCENARIOS ? env.INCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const scenariosNotContaining = env.EXCLUDE_SCENARIOS ? env.EXCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const origins = env.ONLY_INCLUDE_ORIGINS ? env.ONLY_INCLUDE_ORIGINS.split(',').map((s) => s.trim()) : [];

			// Fetch decisions from LAPI
			const decisions = await fetchDecisionsStream(lapiUrl, env.LAPI_KEY, {
				startup: needStartUpFetch,
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

			// Handle HTTP 204 (LAPI has no decisions - clear the active sync target)
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
				// Safe to mark warmed here: the sync target is now in its
				// intended empty state, so a crash at this point doesn't leave
				// decisions unwritten.
				if (needStartUpFetch) {
					await markAsWarmed(env.CROWDSECCFBOUNCERNS);
					logger.info('Cache marked as warmed (LAPI has no decisions)');
				}
				const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
				logger.info('Cleared successfully (LAPI has no decisions)', {
					totalDuration: `${finalDuration}s`,
				});
				return; // Exit early - no further sync needed
			}

			// syncToKv throws on failure, so reaching markAsWarmed below means
			// it fully completed. syncToIpLists instead returns a boolean,
			// since a rate limit or error there is expected, recoverable
			// progress rather than a hard failure — see its own docs.
			let syncSucceeded = true;
			if (syncToKvEnabled) {
				await syncToKv(env, decisions, needStartUpFetch);
			} else {
				syncSucceeded = await syncToIpLists(env, decisions);
			}

			// Mark cache as warmed ONLY after the sync target has captured
			// this run's decisions. If this runs before every write actually
			// landed, a mid-sync crash leaves WARMED_UP=true with some
			// decisions never applied, and the next run does an incremental
			// fetch that never backfills what was missed — a silent
			// enforcement gap.
			if (needStartUpFetch && syncSucceeded) {
				await markAsWarmed(env.CROWDSECCFBOUNCERNS);
				logger.info('Cache marked as warmed (first sync complete)');
			} else if (needStartUpFetch) {
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
}

/**
 * Sync decisions to the Worker's KV store (used by the L7 bouncer worker).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @param {boolean} needStartUpFetch
 */
async function syncToKv(env, decisions, needStartUpFetch) {
	logger.info('Starting KV sync...');

	// Step 1: Get existing IP_RANGES from KV
	const existingRanges = await getIpRanges(env.CROWDSECCFBOUNCERNS);

	// Step 2: Check existing string decisions in KV (only on incremental updates, not first run)
	let existingStringDecisions = new Map();

	if (!needStartUpFetch) {
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
		logger.debug('Startup fetch: skipping existence check (KV is empty)');
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
 * The D1 table (env.LIST_STATE_DB) is the single source of truth for both
 * pending work and current membership — see cloudflare-ip-lists.js for the
 * row shape. Each tick: expired decisions are upserted as
 * list_action='delete' and new decisions as list_action='new' (delete always
 * wins if the same IP appears in both this tick), then a bounded slice of
 * pending deletes/adds is applied to Cloudflare. This makes a large warmup
 * (which can take days at realistic decision volumes) resumable — a rate
 * limit or error mid-tick just leaves the rest pending for next time — and
 * an append-only add / id-targeted remove never overwrites IPs some other
 * process added to the same lists, unlike a full-replace would.
 *
 * On the first sync after a cold start, the caller clears both the table and
 * the managed lists (clearAllIpLists) before this runs, so what's upserted
 * here is a clean full-state pull rather than layered on residue from a
 * previously interrupted warmup. Draining pending adds toward Cloudflare is
 * a separate, ongoing process that continues across ticks regardless of
 * needStartUpFetch — WARMED_UP only means "the initial full pull from LAPI
 * has been captured", not "every pending add has been pushed".
 *
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>} true unless this tick stopped early (rate
 *   limit or error) — an unplaced/still-pending remainder is normal,
 *   expected progress, not a failure.
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
	const db = env.LIST_STATE_DB;

	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	if (lists.length === 0) {
		logger.warn(`No IP Lists found with prefix "${prefix}"; skipping IP list sync`);
		// Nothing we can do without any managed lists; don't block warming on it.
		return true;
	}
	const listNameById = new Map(lists.map((l) => [l.id, l.name]));
	const listIds = lists.map((l) => l.id); // already name-sorted by listManagedIpLists

	// 1/2: split into upsert-ready entries, warning if the same IP shows up
	// in both batches this tick (delete always wins).
	const { newItems, deleteItems } = planUpserts(decisions.new, decisions.deleted, (msg, ctx) => logger.warn(msg, ctx));

	// 3: upsert new decisions (list_action='new' unless already 'listed'),
	// then expired decisions (list_action='delete', unconditionally).
	await upsertNews(db, newItems);
	await upsertDeletes(db, deleteItems);

	// 4: apply every pending delete now — removals aren't paced/batched like
	// adds are, since getting a ban off a list promptly matters more than
	// pacing removals.
	const { deletesByList, queueOnlyDeletes } = await readPendingDeletes(db);
	const confirmedIps = new Set(queueOnlyDeletes); // nothing to remove from Cloudflare; just drop the row

	// Per-list tallies for the completion summary below, so it's clear at a
	// glance which lists were actually touched this tick and by how much.
	const updatedLists = new Map(); // listName -> { added, removed }
	const bumpListStat = (listName, key, n) => {
		const stat = updatedLists.get(listName) || { added: 0, removed: 0 };
		stat[key] += n;
		updatedLists.set(listName, stat);
	};

	let removedCount = 0;
	for (const [listId, toDelete] of deletesByList) {
		const listName = listNameById.get(listId) ?? listId;
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
		for (const { ip } of toDelete) {
			confirmedIps.add(ip);
			removedCount++;
		}
		bumpListStat(listName, 'removed', toDelete.length);
	}
	// Rows Cloudflare confirmed removed, or that were never actually pushed,
	// are done for good — drop them from the table entirely.
	await deleteQueueRows(db, [...confirmedIps]);

	// 5: place a bounded batch of pending adds, packing lists to capacity in
	// order based on current member counts.
	const pendingAdds = await readPendingAdds(db, batchSize);
	let addedCount = 0;
	let unplacedCount = 0;

	if (pendingAdds.length > 0) {
		const listSizes = await readListSizes(db);
		const { addsByList, unplaced } = planAdds(pendingAdds, listIds, listSizes, MAX_ITEMS_PER_LIST);
		unplacedCount = unplaced.length;
		if (unplaced.length > 0) {
			logger.warn(`${unplaced.length} pending IP(s) have no room in any managed list; left pending`);
		}

		for (const [listId, items] of addsByList) {
			const listName = listNameById.get(listId) ?? listId;
			const ips = items.map((i) => i.ip);
			logger.info(`Adding ${ips.length} item(s) to IP list ${listName}...`, {
				list: listName,
				added: ips.length,
			});

			let itemIdByIp;
			try {
				itemIdByIp = await addListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, listId, ips);
			} catch (e) {
				// Deletes and any earlier add iterations already committed above
				// (and via markListed calls below) stay applied; the rest of this
				// tick's adds stay pending for next time.
				return handleIpListError(env, e, `adding items to IP list ${listName}`);
			}

			const placed = items.map((item) => ({ ip: item.ip, itemId: itemIdByIp.get(item.ip) })).filter((p) => p.itemId);
			await markListed(db, listId, placed);
			addedCount += placed.length;
			bumpListStat(listName, 'added', placed.length);
		}
	}

	// Made it through this tick without hitting a rate limit; clear any
	// stale backoff from a previous run so the next tick isn't held back
	// unnecessarily.
	await clearBackoff(env.CROWDSECCFBOUNCERNS);

	logger.info('IP list sync completed successfully', {
		removed: removedCount,
		added: addedCount,
		listsUpdated: [...updatedLists.entries()].map(([list, stat]) => ({ list, ...stat })),
		unplaced: unplacedCount,
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
 * Empty every managed IP list and the D1 table entirely. Used when LAPI
 * reports no decisions at all (HTTP 204), mirroring the KV path's
 * resetAllDecisions.
 * @param {import('./types.js').CrowdSecEnv} env
 */
async function clearAllIpLists(env) {
	logger.info('Clearing all managed IP lists...');

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const db = env.LIST_STATE_DB;
	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	const listNameById = new Map(lists.map((l) => [l.id, l.name]));
	const listedByList = await readAllListed(db);

	const clearedLists = [];
	for (const [listId, members] of listedByList) {
		if (members.length === 0) continue;
		const listName = listNameById.get(listId) ?? listId;

		logger.info(`Emptying IP list ${listName}...`, { list: listName, removed: members.length });
		await removeListItems(
			env.CF_ACCOUNT_ID,
			env.CF_API_TOKEN,
			listId,
			members.map((m) => m.itemId)
		);
		clearedLists.push({ list: listName, removed: members.length });
	}

	await clearQueue(db);

	logger.info('All managed IP lists cleared successfully', { listCount: lists.length, listsUpdated: clearedLists });
}

/* harmony default export */ const src = ({ scheduled });

export { src as default };
