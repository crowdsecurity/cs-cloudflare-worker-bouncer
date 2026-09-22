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

// Holds a single ISO timestamp: don't attempt IP list writes again until
// after this time. Set when Cloudflare returns 429 with a Retry-After we can
// trust; checked at the start of the next sync so we don't burn a cron tick
// re-attempting a call we already know will be rejected.
const IPLIST_BACKOFF_UNTIL_KEY = 'IPLIST_BACKOFF_UNTIL';
// Holds a single ISO timestamp: don't touch D1 again until after this time.
// Set when D1's free-tier daily row-write quota is hit — unlike
// IPLIST_BACKOFF_UNTIL (which only pauses pushing to Cloudflare's API), this
// means D1 itself can't be written to at all, so nothing in syncToIpLists can
// safely proceed: not the upserts, not the deletes, not the adds. The quota
// resets at midnight UTC, not after a fixed delay, so this is a distinct
// mechanism from setIpListBackoff/getIpListBackoffUntil above, not a variant of it.
const D1_BACKOFF_UNTIL_KEY = 'D1_BACKOFF_UNTIL';
// Substring Cloudflare's D1 binding uses for this specific quota error, so we
// can back off precisely for this cause rather than for any D1 write failure
// (e.g. a transient error we'd rather just retry next tick).
const D1_DAILY_WRITE_LIMIT_MESSAGE = "exceeded D1's free tier daily row write limit";
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
	const response = await fetch(url, { method: 'GET', headers: buildApiHeaders(apiToken) });

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
 * Upsert expired decisions into the queue, forcing list_action='delete' 
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 */
export async function upsertDeletes(db, items) {
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
 * Upsert new decisions into the queue as list_action='new'
 *   Unless the row is already 'listed'
 * @param {D1Database} db
 * @param {{ip: string, action: string, until: string}[]} items
 */
export async function upsertNews(db, items) {
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
 * IPs not in lists yet are returned separately so the caller can just drop it from the queue.
 * @param {D1Database} db
 * @returns {Promise<{deletesByList: Map<string, {ip: string, itemId: string}[]>, queueOnlyDeletes: string[]}>}
 */
export async function readPendingDeletes(db) {
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
export async function readAllListed(db) {
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
export async function deleteQueueRows(db, ips) {
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
export async function readPendingAdds(db, limit) {
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
export async function readListSizes(db) {
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
export async function markListed(db, listId, placed) {
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
export async function clearQueue(db) {
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
export async function addListItems(accountId, apiToken, listId, ips) {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`;

	const response = await fetch(url, {
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

	const response = await fetch(url, {
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

		const response = await fetch(url, { method: 'GET', headers: buildApiHeaders(apiToken) });
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
		const response = await fetch(url, { method: 'GET', headers: buildApiHeaders(apiToken) });
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
	const raw = await kvNamespace.get(IPLIST_BACKOFF_UNTIL_KEY);
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
	await kvNamespace.put(IPLIST_BACKOFF_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the backoff deadline, e.g. once it has passed or a sync run
 * completes without hitting a rate limit.
 * @param {KVNamespace} kvNamespace
 */
export async function clearIpListBackoff(kvNamespace) {
	await kvNamespace.delete(IPLIST_BACKOFF_UNTIL_KEY);
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
	const raw = await kvNamespace.get(D1_BACKOFF_UNTIL_KEY);
	if (!raw) return null;

	const until = new Date(raw);
	if (Number.isNaN(until.getTime())) return null;

	return until;
}

// Small safety margin past the actual UTC-midnight reset, in case Cloudflare
// applies it a little late relative to our clock — avoids retrying into a
// quota that hasn't actually reset yet.
const D1_BACKOFF_SAFETY_MARGIN_MS = 10 * 60 * 1000;

/**
 * Record that D1 should not be touched again until shortly after the next
 * UTC midnight, when D1's free-tier daily row-write quota resets.
 * @param {KVNamespace} kvNamespace
 */
export async function setD1BackoffUntilMidnightUTC(kvNamespace) {
	const until = new Date();
	until.setUTCHours(24, 0, 0, 0); // next midnight UTC (today if already before it, rolls to tomorrow if past)
	until.setTime(until.getTime() + D1_BACKOFF_SAFETY_MARGIN_MS);
	await kvNamespace.put(D1_BACKOFF_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the D1 backoff deadline, e.g. once it has passed.
 * @param {KVNamespace} kvNamespace
 */
export async function clearD1Backoff(kvNamespace) {
	await kvNamespace.delete(D1_BACKOFF_UNTIL_KEY);
}

export { MAX_ITEMS_PER_LIST };
