
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
const RESET_KEY = 'RESET';
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

	// Handle eventual HTTP 204 No Content 
	// it used to delete all, but we don't want that anymore
	if (response.status === 204) {
		logger.warn('LAPI returned 204 No Content: not doing anything');
		return {
			new: [],
			deleted: [],
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

;// ./src/core/sync-runner.js
/**
 * Shared scheduled-tick skeleton for both decisions-sync workers (KV and IP
 * Lists). Each worker is a separate compiled script with exactly one sync
 * target, chosen at deploy time rather than by a runtime flag — this module
 * holds everything that's identical either way: env validation, the sync
 * lock, the LAPI pull, and RESET/WARMED_UP handling. The target-specific sync
 * itself is supplied by the caller as `runSync`.
 */




/**
 * @param {import('../types.js').CrowdSecEnv} env
 * @returns {string | null} an error message if validation fails, else null
 */
function validateCommonEnv(env) {
	if (!env.LAPI_URL) return 'LAPI_URL environment variable is not set';
	if (!env.LAPI_KEY) return 'LAPI_KEY secret is not set';
	if (!env.CROWDSECCFBOUNCERNS) return 'CROWDSECCFBOUNCERNS KV namespace is not bound';
	if (!env.CF_ACCOUNT_ID) return 'CF_ACCOUNT_ID environment variable is not set';
	if (!env.CF_API_TOKEN) return 'CF_API_TOKEN secret is not set (required for bulk KV/IP list operations)';
	return null;
}

/**
 * @typedef {Object} SyncHooks
 * @property {(env: import('../types.js').CrowdSecEnv) => string | null} [validateEnv] - extra env validation beyond validateCommonEnv
 * @property {(env: import('../types.js').CrowdSecEnv) => Promise<boolean>} [shouldSkip] - checked right after the lock is acquired, before any LAPI pull; returning true no-ops the entire tick (e.g. waiting out a backoff)
 * @property {(env: import('../types.js').CrowdSecEnv) => Promise<boolean>} needStartUpFetch - whether this tick must be a full LAPI pull
 * @property {(env: import('../types.js').CrowdSecEnv, resetRequested: boolean) => Promise<void>} [onResetRequested] - called once, before the LAPI pull, when RESET was requested
 * @property {(env: import('../types.js').CrowdSecEnv, decisions: import('../types.js').DecisionStreamResponse, needStartUpFetch: boolean) => Promise<boolean>} runSync - performs the actual sync, returns whether it succeeded
 */

/**
 * Run one scheduled tick: validate env, acquire the sync lock, pull decisions
 * from LAPI, run the target-specific sync, release the lock. Swallows all
 * errors (logged, not rethrown) so a failed tick never surfaces as an
 * unhandled Worker exception.
 * @param {ScheduledEvent} event
 * @param {import('../types.js').CrowdSecEnv} env
 * @param {SyncHooks} hooks
 */
async function runScheduledSync(event, env, hooks) {
	const startTime = Date.now();

	logger.info('Decision sync started', { cron: event.cron, scheduledTime: event.scheduledTime });

	try {
		const commonError = validateCommonEnv(env);
		if (commonError) {
			logger.error(commonError);
			return;
		}
		if (hooks.validateEnv) {
			const specificError = hooks.validateEnv(env);
			if (specificError) {
				logger.error(specificError);
				return;
			}
		}

		const lapiUrl = env.LAPI_URL.replace(/\/$/, ''); // Remove trailing slash if present

		// Lock to avoid overlapping syncs from multiple cron ticks or manual runs.
		const lockAcquired = await tryAcquireSyncLock(env.CROWDSECCFBOUNCERNS);
		if (!lockAcquired) {
			logger.info('Sync already in progress, skipping this run');
			return;
		}

		try {
			if (hooks.shouldSkip && (await hooks.shouldSkip(env))) {
				return;
			}

			const needStartUpFetch = await hooks.needStartUpFetch(env);
			logger.info('Determined fetch mode', { startup: needStartUpFetch });

			const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);
			if (resetRequested && hooks.onResetRequested) {
				await hooks.onResetRequested(env, resetRequested);
			}
			if (resetRequested) {
				await clearResetFlag(env.CROWDSECCFBOUNCERNS);
			}

			// Parse optional filter configuration
			const scenariosContaining = env.INCLUDE_SCENARIOS ? env.INCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const scenariosNotContaining = env.EXCLUDE_SCENARIOS ? env.EXCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const origins = env.ONLY_INCLUDE_ORIGINS ? env.ONLY_INCLUDE_ORIGINS.split(',').map((s) => s.trim()) : [];

			const decisions = await fetchDecisionsStream(lapiUrl, env.LAPI_KEY, {
				startup: needStartUpFetch,
				scenariosContaining,
				scenariosNotContaining,
				origins,
			});

			const duration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.info('Decision stream completed successfully', {
				duration: `${duration}s`,
				newDecisions: decisions.new.length,
				deletedDecisions: decisions.deleted.length,
			});

			const syncSucceeded = await hooks.runSync(env, decisions, needStartUpFetch);

			const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
			if (syncSucceeded) {
				logger.info('Decision sync tick finished', { totalDuration: `${finalDuration}s`, syncSucceeded });
			} else {
				logger.warn('Decision sync tick finished without syncing (see warnings above for why)', {
					totalDuration: `${finalDuration}s`,
					syncSucceeded,
				});
			}
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

		// Swallow the error rather than rethrow
		// No advantage throwing + we have enough logs to find out what happened
	}
}

;// ./src/core/ip-list-processor.js
/**
 * IP List Processor
 * Pure helpers for the Cloudflare IP List sync (L3/4 bouncing). Only 'ip'
 * and 'range' scoped decisions apply here — country/AS decisions aren't
 * representable in a Cloudflare IP List.
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

;// ./src/adapters/cloudflare-ip-lists.js
/**
 * Cloudflare IP Lists Adapter
 * Manages membership of CrowdSec-prefixed IP Lists for L3/4 (firewall rule)
 * bouncing. List creation and the firewall rules that reference these lists
 * are provisioned by an external process — this adapter only fills/empties
 * list membership.
 *
 * Stateless: Cloudflare's own list contents are the only source of truth.
 * There is no local index of membership — a GET of the list's current items
 * is how item ids are resolved when a removal is needed.
 */



// Tallies real requests made against the Cloudflare API this tick, broken
// down by endpoint/purpose, so the caller can log them without every call
// site having to track its own count. Reset at the start of each sync run
// via resetRequestCounts.
const requestCounts = {
	cloudflareApi: 0,
	cloudflareApiByEndpoint: {
		listManagedIpLists: 0,
		addListItems: 0,
		removeListItems: 0,
		replaceListItems: 0,
		getListItems: 0,
		pollBulkOperation: 0,
	},
};

/**
 * Reset the per-tick request tallies. Call once at the start of a sync run.
 */
function resetRequestCounts() {
	requestCounts.cloudflareApi = 0;
	for (const key of Object.keys(requestCounts.cloudflareApiByEndpoint)) {
		requestCounts.cloudflareApiByEndpoint[key] = 0;
	}
}

/**
 * fetch wrapper that counts every call toward the Cloudflare API tally, both
 * overall and per calling endpoint/purpose — so a log of the total can also
 * show, e.g., that most of this tick's requests went to pollBulkOperation
 * rather than to the add/remove/replace calls themselves.
 * @param {string} endpoint - key into requestCounts.cloudflareApiByEndpoint
 */
async function trackedFetch(endpoint, url, init) {
	requestCounts.cloudflareApi++;
	requestCounts.cloudflareApiByEndpoint[endpoint] = (requestCounts.cloudflareApiByEndpoint[endpoint] ?? 0) + 1;
	return fetch(url, init);
}

const BACKOFF_IPLIST_UNTIL_KEY = 'BACKOFF_IPLIST_UNTIL';
// Operator-chosen ceiling for a single custom list (Cloudflare's large IP
// Lists have no fixed per-list item cap; this just bounds how full we pack
// one before refusing to add more).
const MAX_ITEMS_PER_LIST = 300000;
const BULK_POLL_INTERVAL_MS = 1000;
const BULK_POLL_TIMEOUT_MS = 120000;

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

function buildApiHeaders(apiToken) {
	return {
		'Authorization': `Bearer ${apiToken}`,
		'Content-Type': 'application/json',
	};
}

/**
 * Discover the IP Lists this worker is allowed to manage: every custom list
 * whose name starts with the configured prefix. Lists are sorted by name so
 * pack-to-full placement (list 1 first) is stable across runs. Includes each
 * list's num_items straight from this same response — Cloudflare's own
 * count of its current membership — so callers can log/compare it without an
 * extra request.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} prefix
 * @returns {Promise<{id: string, name: string, numItems: number}[]>}
 */
async function listManagedIpLists(accountId, apiToken, prefix) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists`;
	const response = await trackedFetch('listManagedIpLists', url, { method: 'GET', headers: buildApiHeaders(apiToken) });

	if (!response.ok) {
		await throwApiError('Failed to list IP Lists', response);
	}

	const data = await response.json();
	const lists = (data.result || [])
		.filter((list) => list.kind === 'ip' && list.name.startsWith(prefix))
		.map((list) => ({ id: list.id, name: list.name, numItems: list.num_items ?? 0 }))
		.sort((a, b) => a.name.localeCompare(b.name));

	logger.debug(`Discovered ${lists.length} managed IP list(s) with prefix "${prefix}"`);

	return lists;
}

/**
 * Cloudflare error code for "invalid or expired cursor" on a list-items page
 * request — the cursor is a short-lived opaque token and can expire mid-walk
 * on a large list, especially under slower/rate-limited conditions.
 */
const EXPIRED_CURSOR_ERROR_CODE = 10027;

/**
 * @param {Response} response
 * @returns {Promise<boolean>} true if the response body is Cloudflare's
 *   "invalid or expired cursor" error
 */
async function isExpiredCursorError(response) {
	const clone = response.clone();
	try {
		const data = await clone.json();
		return (data.errors || []).some((e) => e.code === EXPIRED_CURSOR_ERROR_CODE);
	} catch {
		return false;
	}
}

/**
 * Page through a list's full current membership once, from the start.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @returns {Promise<Map<string, string>>} ip -> Cloudflare item id
 */
async function fetchAllListItems(accountId, apiToken, listId) {
	const items = new Map();
	let cursor = null;

	do {
		const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`);
		// Cloudflare's documented max per_page for this endpoint is 500;
		// asking for more risks an inconsistent/invalid cursor rather than a
		// clean clamp or rejection.
		url.searchParams.set('per_page', '500');
		if (cursor) url.searchParams.set('cursor', cursor);

		const response = await trackedFetch('getListItems', url, { method: 'GET', headers: buildApiHeaders(apiToken) });
		if (!response.ok) {
			if (await isExpiredCursorError(response)) {
				throw new ExpiredCursorError();
			}
			await throwApiError(`Failed to read items for list ${listId}`, response);
		}

		const data = await response.json();
		for (const item of data.result || []) {
			items.set(item.ip, item.id);
		}

		// Cloudflare documents this as result_info.cursors.after; keep
		// checking the older/undocumented result_info.cursor shape too in
		// case it's ever returned instead, since reading the wrong field
		// would silently stop pagination after page 1 without any error.
		cursor = data.result_info?.cursors?.after || data.result_info?.cursor || null;
	} while (cursor);

	return items;
}

class ExpiredCursorError extends Error {}

// How many full from-scratch attempts to make when the cursor keeps coming
// back invalid/expired. A single retry only covers a one-off timeout; if
// something else is mutating the list concurrently (a manual script, an
// overlapping worker run, ...) the cursor can be invalidated repeatedly, so
// this gives a few tries before actually giving up.
const MAX_LIST_ITEMS_ATTEMPTS = 3;

/**
 * Page through a list's full current membership. The pagination cursor is
 * short-lived and can expire — on the very first page as well as mid-walk
 * (Cloudflare error 10027) — either from simple timeout or because another
 * process (a manual script, an overlapping run, ...) is writing to the same
 * list concurrently and invalidating it. Retries the whole walk from the
 * beginning a few times before giving up, rather than failing the whole
 * tick over a single stale cursor.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @returns {Promise<Map<string, string>>} ip -> Cloudflare item id
 */
async function getListItems(accountId, apiToken, listId) {
	for (let attempt = 1; attempt <= MAX_LIST_ITEMS_ATTEMPTS; attempt++) {
		try {
			return await fetchAllListItems(accountId, apiToken, listId);
		} catch (e) {
			if (!(e instanceof ExpiredCursorError) || attempt === MAX_LIST_ITEMS_ATTEMPTS) throw e;
			logger.warn(
				`List-items cursor expired for list ${listId} (attempt ${attempt}/${MAX_LIST_ITEMS_ATTEMPTS}); this can happen from a plain timeout or because another process is writing to the list concurrently — restarting pagination from the beginning`
			);
		}
	}
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
 */
async function addListItems(accountId, apiToken, listId, ips) {
	if (ips.length === 0) return;

	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`;

	const response = await trackedFetch('addListItems', url, {
		method: 'POST',
		headers: buildApiHeaders(apiToken),
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

	const response = await trackedFetch('removeListItems', url, {
		method: 'DELETE',
		headers: buildApiHeaders(apiToken),
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
 * PUT a list's full desired membership and wait for the resulting bulk
 * operation to complete. Used for the startup pull (full replace) and by
 * TEST_MODE.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @param {string[]} ips - the list's full desired membership after this call
 */
async function replaceListItems(accountId, apiToken, listId, ips) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`;

	const response = await trackedFetch('replaceListItems', url, {
		method: 'PUT',
		headers: buildApiHeaders(apiToken),
		body: JSON.stringify(ips.map((ip) => ({ ip }))),
	});

	if (!response.ok) {
		await throwApiError(`Failed to replace items on list ${listId}`, response);
	}

	const data = await response.json();
	const operationId = data.result?.operation_id;
	if (operationId) {
		await pollBulkOperation(accountId, apiToken, operationId);
	}
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
		const response = await trackedFetch('pollBulkOperation', url, { method: 'GET', headers: buildApiHeaders(apiToken) });
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
async function getIpListBackoffUntil(kvNamespace) {
	const raw = await kvNamespace.get(BACKOFF_IPLIST_UNTIL_KEY);
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
async function setIpListBackoff(kvNamespace, retryAfterSeconds) {
	const until = new Date(Date.now() + retryAfterSeconds * 1000);
	await kvNamespace.put(BACKOFF_IPLIST_UNTIL_KEY, until.toISOString());
}

/**
 * Record that IP list writes should not be attempted again for the given
 * number of hours — used after a startup pull's PUT (or the list lookup
 * before it) succeeds or fails, to pace how often a full-list PUT is tried.
 * @param {KVNamespace} kvNamespace
 * @param {number} hours
 */
async function setIpListBackoffHours(kvNamespace, hours) {
	const until = new Date(Date.now() + hours * 60 * 60 * 1000);
	await kvNamespace.put(BACKOFF_IPLIST_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the backoff deadline, e.g. once it has passed or a sync run
 * completes without hitting a rate limit.
 * @param {KVNamespace} kvNamespace
 */
async function clearIpListBackoff(kvNamespace) {
	await kvNamespace.delete(BACKOFF_IPLIST_UNTIL_KEY);
}



;// ./src/index-ip-lists.js
/**
 * CrowdSec Decisions Sync Worker — IP Lists target
 * Periodically fetches security decisions from CrowdSec LAPI and syncs
 * 'ip'/'range' scoped decisions into a single Cloudflare IP List (used for L3/4 firewall-rule bouncing).
 */







const DEFAULT_IP_LIST_PREFIX = 'cs_';
const TEST_MODE_LIST_NAME = 'cs_00';
const TEST_MODE_IP_COUNT = 10;
// After every startup (full-replace) tick, wait this long before the next
// pull or any other IP-list action — win or lose, so a failing startup
// (list lookup or PUT) can't be retried in a tight loop either.
const IP_LIST_STARTUP_BACKOFF_HOURS = 25;

/**
 * Resolve the single IP list this worker manages (by IP_LIST_PREFIX),
 * warning if more than one list matches.
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {string} prefix
 * @returns {Promise<{id: string, name: string, numItems: number} | null>}
 */
async function resolveManagedList(env, prefix) {
	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	if (lists.length === 0) {
		return null;
	}
	if (lists.length > 1) {
		logger.warn(
			`IP-list mode manages exactly one list but found ${lists.length} matching prefix "${prefix}"; using the first (name-sorted) and leaving the rest untouched`,
			{ lists: lists.map((l) => l.name) }
		);
	}
	return lists[0];
}

/**
 * Startup tick: 
 *  - Always a full LAPI pull
 *  - PUT whole list (capped) into the single managed list
 *  - On success, flag warmed up + Flag a 25h backoff timer to avoid rate limiting
 *    - The warmed up sync will take over
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>}
 */
async function syncToIpListStartup(env, decisions) {
	logger.info('Starting IP list sync (startup: full replace)...');
	resetRequestCounts();

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const maxItemsPerList = env.IP_LIST_MAX_ITEMS_PER_LIST ? parseInt(env.IP_LIST_MAX_ITEMS_PER_LIST, 10) : MAX_ITEMS_PER_LIST;

	try {
		// Dedupe: LAPI can emit multiple decisions for the same IP (different
		// scenarios/origins), which would otherwise inflate the list and the
		// truncation count for no reason.
		const allIps = [...new Set(filterIpListScopes(decisions.new).map((d) => d.value))];

		const list = await resolveManagedList(env, prefix);
		if (!list) {
			logger.error(`No IP List found with prefix "${prefix}"; pausing ${IP_LIST_STARTUP_BACKOFF_HOURS}h before retrying`);
			await setIpListBackoffHours(env.CROWDSECCFBOUNCERNS, IP_LIST_STARTUP_BACKOFF_HOURS);
			return false;
		}

		let ipsToPush = allIps;
		if (allIps.length > maxItemsPerList) {
			const truncatedCount = allIps.length - maxItemsPerList;
			logger.error(
				`Active decisions (${allIps.length}) exceed IP_LIST_MAX_ITEMS_PER_LIST (${maxItemsPerList}); truncating — ${truncatedCount} IP(s) will NOT be in list ${list.name} this tick`,
				{ list: list.name, totalDecisions: allIps.length, maxItemsPerList, truncatedCount }
			);
			ipsToPush = allIps.slice(0, maxItemsPerList);
		}

		logger.info(`Replacing IP list ${list.name} entirely...`, {
			list: list.name,
			size: ipsToPush.length,
			max: maxItemsPerList,
		});
		await replaceListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, ipsToPush);

		await markAsWarmed(env.CROWDSECCFBOUNCERNS);
		logger.info('IP list startup sync completed successfully', { list: list.name, size: ipsToPush.length });
		return true;
	} catch (e) {
		return handleIpListError(env, e, 'replacing the IP list on startup');
	} finally {
		// Win or lose, pace the next IP-list action 25h out — a failed
		// startup leaves WARMED_UP false, so it just retries as a startup
		// again once the pause clears.
		await setIpListBackoffHours(env.CROWDSECCFBOUNCERNS, IP_LIST_STARTUP_BACKOFF_HOURS);
		logger.info('IP list startup sync request tally', {
			cloudflareApiRequests: requestCounts.cloudflareApi,
			cloudflareApiByEndpoint: { ...requestCounts.cloudflareApiByEndpoint },
		});
	}
}

/**
 * Warmed (incremental) tick: decisions.new/decisions.deleted are a delta.
 * Adds go via plain POST, removes via plain DELETE (never a full-replace
 * PUT) — item ids for removes are resolved by reading the list's current
 * contents first, only when there's actually something to delete.
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>}
 */
async function syncToIpListWarmed(env, decisions) {
	logger.info('Starting IP list sync (warmed: add/remove)...');
	resetRequestCounts();

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const maxItemsPerList = env.IP_LIST_MAX_ITEMS_PER_LIST ? parseInt(env.IP_LIST_MAX_ITEMS_PER_LIST, 10) : MAX_ITEMS_PER_LIST;

	const newIps = [...new Set(filterIpListScopes(decisions.new).map((d) => d.value))];
	const deletedIps = [...new Set(filterIpListScopes(decisions.deleted).map((d) => d.value))];

	if (newIps.length === 0 && deletedIps.length === 0) {
		logger.info('No ip/range-scoped decisions this tick; nothing to do');
		return true;
	}

	try {
		const list = await resolveManagedList(env, prefix);
		if (!list) {
			logger.warn(`No IP List found with prefix "${prefix}"; skipping this tick (${newIps.length} add(s), ${deletedIps.length} removal(s) not applied)`);
			return true;
		}

		let itemIdByIp = new Map();
		if (deletedIps.length > 0) {
			try {
				itemIdByIp = await getListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id);
			} catch (e) {
				return handleIpListError(env, e, `reading current items of list ${list.name} before removals`);
			}
		}
		const itemIdsToRemove = deletedIps.map((ip) => itemIdByIp.get(ip)).filter((id) => id !== undefined);
		const notListed = deletedIps.length - itemIdsToRemove.length;
		if (notListed > 0) {
			logger.warn(`${notListed} IP(s) reported as expired were not found in list ${list.name}; nothing to remove for them`, { list: list.name });
		}

		// Clamp adds against the list's own live size (net of this tick's
		// removals) so a tick can never push the real list over
		// maxItemsPerList. Anything clamped off is simply not added this
		// tick — there's no local queue to retry it from later, so it's
		// lost until the next startup pull picks it back up.
		const sizeAfterDeletes = Math.max(0, list.numItems - itemIdsToRemove.length);
		const available = Math.max(0, maxItemsPerList - sizeAfterDeletes);
		let ipsToAdd = newIps;
		if (ipsToAdd.length > available) {
			const droppedCount = ipsToAdd.length - available;
			logger.error(
				`List ${list.name} has no room for ${droppedCount} of ${ipsToAdd.length} new IP(s) (maxItemsPerList=${maxItemsPerList}); they will NOT be added this tick and won't be retried until the next startup pull`,
				{ list: list.name, planned: ipsToAdd.length, available, dropped: droppedCount }
			);
			ipsToAdd = ipsToAdd.slice(0, available);
		}

		// Alternate delete/add order by day parity — a diagnostic for
		// suspected Cloudflare rate-limit starvation: if one op eats the
		// tick's rate-limit budget (or the account's single pending-bulk-
		// operation slot) before the other runs, the other never happens on
		// a day where it always goes second. Alternating lets us see
		// whether the order correlates with that pattern.
		const performAddFirst = new Date().getUTCDate() % 2 === 0;
		logger.info(`Updating IP list ${list.name} via add/remove...`, {
			list: list.name,
			added: ipsToAdd.length,
			removed: itemIdsToRemove.length,
			order: performAddFirst ? 'add-then-delete' : 'delete-then-add',
		});

		let addedCount = 0;
		let removedCount = 0;
		try {
			const doAdd = async () => {
				await addListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, ipsToAdd);
				addedCount = ipsToAdd.length;
			};
			const doRemove = async () => {
				await removeListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, itemIdsToRemove);
				removedCount = itemIdsToRemove.length;
			};
			if (performAddFirst) {
				await doAdd();
				await doRemove();
			} else {
				await doRemove();
				await doAdd();
			}
		} catch (e) {
			const remainingAdds = ipsToAdd.length - addedCount;
			const remainingRemoves = itemIdsToRemove.length - removedCount;
			logger.error(`Failed partway through updating list ${list.name}; ${remainingAdds} add(s) and ${remainingRemoves} removal(s) did not complete this tick`, {
				list: list.name,
				added: addedCount,
				removed: removedCount,
				remainingAdds,
				remainingRemoves,
			});
			return handleIpListError(env, e, `updating IP list ${list.name} (add/remove)`);
		}

		await clearIpListBackoff(env.CROWDSECCFBOUNCERNS);
		logger.info(`IP list ${list.name} updated successfully`, { list: list.name, added: addedCount, removed: removedCount });
		return true;
	} finally {
		logger.info('IP list warmed sync request tally', {
			cloudflareApiRequests: requestCounts.cloudflareApi,
			cloudflareApiByEndpoint: { ...requestCounts.cloudflareApiByEndpoint },
		});
	}
}

/**
 * Test mode: pulls the full decision set (startup=true, done by the caller)
 * and PUTs only the first TEST_MODE_IP_COUNT ip/range-scoped IPs into the
 * fixed TEST_MODE_LIST_NAME list, bypassing the normal startup/warmed sync.
 * For poking a known-small, known list to sanity check credentials/API
 * access without touching real traffic-facing lists.
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>}
 */
async function runTestModeSync(env, decisions) {
	logger.info(`Starting test mode sync: PUTting up to ${TEST_MODE_IP_COUNT} IP(s) into ${TEST_MODE_LIST_NAME}...`);
	resetRequestCounts();

	try {
		const ips = [...new Set(filterIpListScopes(decisions.new).map((d) => d.value))].slice(0, TEST_MODE_IP_COUNT);

		const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, TEST_MODE_LIST_NAME);
		const list = lists.find((l) => l.name === TEST_MODE_LIST_NAME);
		if (!list) {
			logger.error(`Test mode list "${TEST_MODE_LIST_NAME}" not found; create it manually first`);
			return false;
		}

		await replaceListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, ips);
		logger.info(`Test mode: successfully put ${ips.length} IP(s) into ${TEST_MODE_LIST_NAME}`, {
			list: TEST_MODE_LIST_NAME,
			count: ips.length,
			ips,
		});
		return true;
	} catch (e) {
		return handleIpListError(env, e, `test mode PUT into ${TEST_MODE_LIST_NAME}`);
	} finally {
		logger.info('Test mode sync request tally', {
			cloudflareApiRequests: requestCounts.cloudflareApi,
			cloudflareApiByEndpoint: { ...requestCounts.cloudflareApiByEndpoint },
		});
	}
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
		await setIpListBackoff(env.CROWDSECCFBOUNCERNS, e.retryAfterSeconds);
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
 * @param {ScheduledEvent} event
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {ExecutionContext} _ctx
 */
async function scheduled(event, env, _ctx) {
	// TEST_MODE only PUT 10 IPs to test rate limiting
	const testModeEnabled = env.TEST_MODE === 'true';

	await runScheduledSync(event, env, {
		shouldSkip: async (env) => {
			const ipListBackoffUntil = await getIpListBackoffUntil(env.CROWDSECCFBOUNCERNS);
			if (ipListBackoffUntil && ipListBackoffUntil > new Date()) {
				logger.warn('Waiting out a previous rate limit or post-startup pause; doing nothing this tick', {
					backoffUntil: ipListBackoffUntil.toISOString(),
				});
				return true;
			}
			return false;
		},
		needStartUpFetch: async (env) => {
			if (testModeEnabled) return true;
			return needWarmUp(env.CROWDSECCFBOUNCERNS);
		},
		onResetRequested: async () => {
			// IP-list mode has nothing to proactively clear on RESET: it just
			// forces the next tick to be a startup pull, whose PUT already
			// replaces the list's entire contents outright.
			logger.info('RESET requested: next IP list tick will be a full startup pull (PUT replaces the list outright)');
		},
		runSync: async (env, decisions, needStartUpFetch) => {
			if (testModeEnabled) {
				return runTestModeSync(env, decisions);
			}
			return needStartUpFetch ? syncToIpListStartup(env, decisions) : syncToIpListWarmed(env, decisions);
		},
	});
}

/* harmony default export */ const index_ip_lists = ({ scheduled });

export { index_ip_lists as default };
