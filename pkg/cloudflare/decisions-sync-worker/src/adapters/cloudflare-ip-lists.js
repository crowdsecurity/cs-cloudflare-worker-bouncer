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

import logger from '../utils/logger.js';

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
 * Read the sharded membership index for every managed list.
 * @param {KVNamespace} kvNamespace
 * @param {{id: string, name: string}[]} lists
 * @returns {Promise<Map<string, Map<string, {itemId: string, action: string, until: string}>>>} listName -> (ip -> entry)
 */
export async function readIndex(kvNamespace, lists) {
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
export async function writeIndexShard(kvNamespace, listName, members) {
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
export async function upsertQueue(db, items, listAction) {
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
export async function readQueueBatch(db, limit) {
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
export async function deleteQueueRows(db, ips) {
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
export async function clearQueue(db) {
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
export async function getBackoffUntil(kvNamespace) {
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
export async function setBackoff(kvNamespace, retryAfterSeconds) {
	const until = new Date(Date.now() + retryAfterSeconds * 1000);
	await kvNamespace.put(BACKOFF_UNTIL_KEY, until.toISOString());
}

/**
 * Clear the backoff deadline, e.g. once it has passed or a sync run
 * completes without hitting a rate limit.
 * @param {KVNamespace} kvNamespace
 */
export async function clearBackoff(kvNamespace) {
	await kvNamespace.delete(BACKOFF_UNTIL_KEY);
}

export { MAX_ITEMS_PER_LIST };
