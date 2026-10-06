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

import logger from '../utils/logger.js';

// Tallies real requests made against each quota-metered backend this tick —
// D1 statements (prepare().run()/.all(), each batch() entry) and Cloudflare
// API calls (fetch, broken down by endpoint/purpose) — so the caller can log
// them without every call site having to track its own count. Reset at the
// start of each syncToIpLists/clearAllIpLists run via resetRequestCounts.
export const requestCounts = {
	d1: 0,
	cloudflareApi: 0,
	cloudflareApiByEndpoint: {
		listManagedIpLists: 0,
		addListItems: 0,
		removeListItems: 0,
		replaceListItems: 0,
		resolveItemIds: 0,
		pollBulkOperation: 0,
	},
};

/**
 * Reset the per-tick request tallies. Call once at the start of a sync run.
 */
export function resetRequestCounts() {
	requestCounts.d1 = 0;
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

/**
 * Run a single D1 statement and count it as one D1 request.
 * @param {D1PreparedStatement} stmt
 * @param {'run' | 'all'} method
 */
async function d1Exec(stmt, method) {
	requestCounts.d1++;
	return stmt[method]();
}

/**
 * Run a D1 batch and count every statement in it — each bound statement in
 * a batch() call is a separate row-write against D1's daily quota, even
 * though they're sent as one network round trip.
 * @param {D1Database} db
 * @param {D1PreparedStatement[]} statements
 */
async function d1BatchExec(db, statements) {
	requestCounts.d1 += statements.length;
	return db.batch(statements);
}

const BACKOFF_IPLIST_UNTIL_KEY = 'BACKOFF_IPLIST_UNTIL';
const BACKOFF_D1_UNTIL_KEY = 'BACKOFF_D1__UNTIL';
// Substring Cloudflare's D1 binding uses for this specific quota error, so we
// can back off precisely for this cause rather than for any D1 write failure
// (e.g. a transient error we'd rather just retry next tick).
const D1_DAILY_WRITE_LIMIT_MESSAGE = "exceeded D1's free tier daily row write limit";
// Operator-chosen ceiling for a single custom list (Cloudflare's large IP
// Lists have no fixed per-list item cap; this just bounds how full we pack
// one before moving to the next).
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
export class CloudflareApiError extends Error {
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
export async function listManagedIpLists(accountId, apiToken, prefix) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists`;
	const response = await trackedFetch('listManagedIpLists', url, { method: 'GET', headers: buildApiHeaders(apiToken) });

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

// Chunk size for the JSON-array upserts below. Binding the whole batch as
// one json_each(?) parameter means statement count no longer scales with row
// count the way the old one-param-per-column VALUES list did — each
// statement now binds exactly 1 param, so the 100-bound-param limit is moot.
// The real ceiling is the serialized JSON blob's size: at ~75 bytes/row
// (ip + action + until) this keeps it around 75KB, comfortably under both
// D1's 100KB SQL statement length limit (it's undocumented whether bound
// parameter bytes count toward that figure, so this stays conservative
// rather than assuming they don't) and the 2MB max bound-value size.
const D1_MAX_ROWS_PER_JSON_STATEMENT = 1000;

/**
 * Upsert expired decisions into the queue, forcing list_action='delete'.
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 */
export async function upsertDeletes(db, items) {
	if (items.length === 0) return;

	const chunks = chunk(items, D1_MAX_ROWS_PER_JSON_STATEMENT);
	const statements = chunks.map((rows) =>
		db
			.prepare(
				// The WHERE true is required, not decorative: SQLite's parser
				// otherwise can't tell this UPSERT's "ON CONFLICT" apart from
				// a join's "ON" after INSERT...SELECT, and fails with a syntax
				// error right at "ON CONFLICT" (confirmed locally) — this is
				// SQLite's own documented workaround for that ambiguity.
				`INSERT INTO ip_list_state (ip, action, until, list_action)
				 SELECT value ->> '$.ip', value ->> '$.action', value ->> '$.until', 'delete'
				 FROM json_each(?)
				 WHERE true
				 ON CONFLICT(ip) DO UPDATE SET action = excluded.action, until = excluded.until, list_action = 'delete'`
			)
			.bind(JSON.stringify(rows))
	);

	await d1BatchExec(db, statements);
}

/**
 * Upsert new decisions into the queue as list_action='new', unless the row
 * is already 'listed'.
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 */
export async function upsertNews(db, items) {
	if (items.length === 0) return;

	const chunks = chunk(items, D1_MAX_ROWS_PER_JSON_STATEMENT);
	const statements = chunks.map((rows) =>
		db
			.prepare(
				// WHERE true: is requiered //see upsertDeletes' comment above the same line.
				`INSERT INTO ip_list_state (ip, action, until, list_action)
				 SELECT value ->> '$.ip', value ->> '$.action', value ->> '$.until', 'new'
				 FROM json_each(?)
				 WHERE true
				 ON CONFLICT(ip) DO UPDATE SET
				   action = excluded.action,
				   until = excluded.until,
				   list_action = CASE WHEN ip_list_state.list_action != 'listed' THEN excluded.list_action ELSE ip_list_state.list_action END`
			)
			.bind(JSON.stringify(rows))
	);

	await d1BatchExec(db, statements);
}

/**
 * Read every row pending deletion, grouped by the list it's currently in.
 * IPs not in lists yet are returned separately so the caller can just drop it from the queue.
 * @param {D1Database} db
 * @returns {Promise<{deletesByList: Map<string, {ip: string, itemId: string}[]>, queueOnlyDeletes: string[]}>}
 */
export async function readPendingDeletes(db) {
	const result = await d1Exec(db.prepare("SELECT ip, list_id, item_id FROM ip_list_state WHERE list_action = 'delete'"), 'all');

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
 * clearAllIpLists (reset) to empty every managed list wholesale —
 * the normal per-tick flow never needs "all listed rows" in one shot.
 * @param {D1Database} db
 * @returns {Promise<Map<string, {ip: string, itemId: string}[]>>} list_id -> members
 */
export async function readAllListed(db) {
	const result = await d1Exec(db.prepare("SELECT ip, list_id, item_id FROM ip_list_state WHERE list_action = 'listed'"), 'all');

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
export async function deleteQueueRows(db, ips) {
	if (ips.length === 0) return;

	// Each bound ip is 1 param, so up to 100 fit in one IN (...) statement.
	const chunks = chunk(ips, 100);
	const statements = chunks.map((rows) => {
		const placeholders = rows.map(() => '?').join(', ');
		return db.prepare(`DELETE FROM ip_list_state WHERE ip IN (${placeholders})`).bind(...rows);
	});

	await d1BatchExec(db, statements);
}

/**
 * Read up to `limit` rows still pending an add (list_action='new').
 * @param {D1Database} db
 * @param {number} limit
 * @returns {Promise<{ip: string, action: string, until: string}[]>}
 */
export async function readPendingAdds(db, limit) {
	const stmt = db.prepare("SELECT ip, action, until FROM ip_list_state WHERE list_action = 'new' LIMIT ?").bind(limit);
	const result = await d1Exec(stmt, 'all');
	return result.results || [];
}

/**
 * Mark a batch of rows as confirmed members of a list, once Cloudflare has
 * accepted the add.
 * @param {D1Database} db
 * @param {string} listId
 * @param {{ip: string, itemId: string}[]} placed
 */
export async function markListed(db, listId, placed) {
	if (placed.length === 0) return;

	const stmt = db.prepare("UPDATE ip_list_state SET list_action = 'listed', list_id = ?, item_id = ? WHERE ip = ?");
	await d1BatchExec(db, placed.map((p) => stmt.bind(listId, p.itemId, p.ip)));
}

/**
 * Delete every row from the D1 queue table. Used when LAPI reports no
 * decisions at all (HTTP 204), or on the first sync after a cold start,
 * mirroring the KV path's resetAllDecisions.
 * @param {D1Database} db
 */
export async function clearQueue(db) {
	await d1Exec(db.prepare('DELETE FROM ip_list_state'), 'run');
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
export async function addListItems(accountId, apiToken, listId, ips) {
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
export async function removeListItems(accountId, apiToken, listId, itemIds) {
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
 * Replace a list's entire membership in one request (removes everything not
 * in `ips`, adds everything in `ips` that isn't already there), and poll the
 * resulting bulk operation until it completes. One request either way, but
 * every item in `ips` counts against Cloudflare's item-modifications quota —
 * unlike addListItems/removeListItems, which only count the actual delta —
 * so callers should only reach for this when the full list is cheaper than
 * the delta (see chooseListUpdateStrategy).
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @param {string[]} ips - the list's full desired membership after this call
 * @returns {Promise<Map<string, string>>} ip -> Cloudflare item id, for every item in `ips`
 */
export async function replaceListItems(accountId, apiToken, listId, ips) {
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

	return resolveItemIds(accountId, apiToken, listId, ips);
}

/**
 * Decide whether replacing a list's entire membership in one PUT is cheaper,
 * in Cloudflare item-modifications (the 1M/12h quota), than adding/removing
 * just the delta via separate POST/DELETE calls. PUT counts every item in
 * the new body as a modification; POST+DELETE only count what actually
 * changed — so PUT only wins when the list is smaller than the delta being
 * applied to it (e.g. still filling up during warmup), never once a list is
 * large and mostly stable.
 * @param {number} currentSize - members in the list before this tick's changes
 * @param {number} addCount
 * @param {number} removeCount
 * @returns {'put' | 'post-delete'}
 */
export function chooseListUpdateStrategy(currentSize, addCount, removeCount) {
	const finalSize = currentSize - removeCount + addCount;
	const deltaCost = addCount + removeCount;
	return finalSize < deltaCost ? 'put' : 'post-delete';
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

		const response = await trackedFetch('resolveItemIds', url, { method: 'GET', headers: buildApiHeaders(apiToken) });
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
export async function getIpListBackoffUntil(kvNamespace) {
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
export async function setIpListBackoff(kvNamespace, retryAfterSeconds) {
	const until = new Date(Date.now() + retryAfterSeconds * 1000);
	await kvNamespace.put(BACKOFF_IPLIST_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the backoff deadline, e.g. once it has passed or a sync run
 * completes without hitting a rate limit.
 * @param {KVNamespace} kvNamespace
 */
export async function clearIpListBackoff(kvNamespace) {
	await kvNamespace.delete(BACKOFF_IPLIST_UNTIL_KEY);
}

/**
 * True if `e` is D1's free-tier daily row-write quota error.
 * @param {unknown} e
 * @returns {boolean}
 */
export function isD1DailyWriteLimitError(e) {
	return e instanceof Error && e.message.includes(D1_DAILY_WRITE_LIMIT_MESSAGE);
}

/**
 * Read the current D1 backoff deadline, if any.
 * @param {KVNamespace} kvNamespace
 * @returns {Promise<Date | null>} null if there's no active backoff
 */
export async function getD1BackoffUntil(kvNamespace) {
	const raw = await kvNamespace.get(BACKOFF_D1_UNTIL_KEY);
	if (!raw) return null;

	const until = new Date(raw);
	if (Number.isNaN(until.getTime())) return null;

	return until;
}

// Small safety margin past the actual UTC-midnight reset, in case Cloudflare
// applies it a little late relative to our clock — avoids retrying into a
// quota that hasn't actually reset yet.
const BACKOFF_D1_SAFETY_MARGIN_MS = 10 * 60 * 1000;

/**
 * Record that D1 should not be touched again until shortly after the next
 * UTC midnight, when D1's free-tier daily row-write quota resets.
 * @param {KVNamespace} kvNamespace
 */
export async function setD1BackoffUntilMidnightUTC(kvNamespace) {
	const until = new Date();
	until.setUTCHours(24, 0, 0, 0); // next midnight UTC (today if already before it, rolls to tomorrow if past)
	until.setTime(until.getTime() + BACKOFF_D1_SAFETY_MARGIN_MS);
	await kvNamespace.put(BACKOFF_D1_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the D1 backoff deadline, e.g. once it has passed.
 * @param {KVNamespace} kvNamespace
 */
export async function clearD1Backoff(kvNamespace) {
	await kvNamespace.delete(BACKOFF_D1_UNTIL_KEY);
}

export { MAX_ITEMS_PER_LIST };
