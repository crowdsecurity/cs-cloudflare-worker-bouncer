
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

;// ./src/index.js
/**
 * CrowdSec Autonomous Decisions Sync Worker
 * Periodically fetches security decisions from CrowdSec LAPI and updates Cloudflare KV (CROWDSECCFBOUNCERNS) storage
 */






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
			// Validate required environment variables
			if (!env.LAPI_URL) {
				logger.error('LAPI_URL environment variable is not set');
				return;
			}

			if (!env.LAPI_KEY) {
				logger.error('LAPI_KEY secret is not set');
				return;
			}

			if (!env.CROWDSECCFBOUNCERNS) {
				logger.error('CROWDSECCFBOUNCERNS KV namespace is not bound');
				return;
			}

			if (!env.CF_ACCOUNT_ID) {
				logger.error('CF_ACCOUNT_ID environment variable is not set');
				return;
			}

			if (!env.CF_KV_NAMESPACE_ID) {
				logger.error('CF_KV_NAMESPACE_ID environment variable is not set');
				return;
			}

			if (!env.CF_API_TOKEN) {
				logger.error('CF_API_TOKEN secret is not set (required for bulk KV operations)');
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
				// Check if reset is requested
				const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);
				if (resetRequested) {
					logger.info('RESET requested: clearing all decision keys from KV...');
					await resetAllDecisions(
						env.CF_ACCOUNT_ID,
						env.CF_KV_NAMESPACE_ID,
						env.CF_API_TOKEN,
						env.CROWDSECCFBOUNCERNS
					);
					logger.info('KV reset completed, proceeding with fresh decision sync');
				}

				// Determine if this is the first fetch
				const isFirst = await isFirstFetch(env.CROWDSECCFBOUNCERNS);
				logger.info('Fetch type determined', { isFirstFetch: isFirst });

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
					logger.info('LAPI has no decisions (204): clearing all decision keys from KV...');
					await resetAllDecisions(
						env.CF_ACCOUNT_ID,
						env.CF_KV_NAMESPACE_ID,
						env.CF_API_TOKEN,
						env.CROWDSECCFBOUNCERNS
					);
					// Safe to mark warmed here: KV is now in its intended empty state,
					// so a crash at this point doesn't leave decisions unwritten.
					if (isFirst) {
						await markAsWarmed(env.CROWDSECCFBOUNCERNS);
						logger.info('Cache marked as warmed (LAPI has no decisions)');
					}
					const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
					logger.info('KV cleared successfully (LAPI has no decisions)', {
						totalDuration: `${finalDuration}s`,
					});
					return; // Exit early - no further sync needed
				}

				// ====================
				// SYNC TO KV STORE
				// ====================

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
					await batchWriteStringBasedDecisions(
						env.CF_ACCOUNT_ID,
						env.CF_KV_NAMESPACE_ID,
						env.CF_API_TOKEN,
						newProcessed.stringEntries
					);
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

				// Step 9: Mark cache as warmed ONLY after all KV writes have succeeded.
				// If this runs before the writes, a mid-sync crash leaves WARMED_UP=true
				// with an empty KV, and the next run does an incremental fetch that
				// never backfills the missed decisions — a silent enforcement gap.
				if (isFirst) {
					await markAsWarmed(env.CROWDSECCFBOUNCERNS);
					logger.info('Cache marked as warmed (first sync complete)');
				}

				// Final summary
				const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);

				logger.info('KV sync completed successfully', {
					totalDuration: `${finalDuration}s`,
					stringWritten: newProcessed.stringEntries.length,
					stringDeleted: deletedProcessed.stringKeysToDelete.length,
					rangesCount: Object.keys(finalRanges).length,
				});
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
