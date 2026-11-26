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

import logger from '../utils/logger.js';

// Tallies real requests made against the Cloudflare API this tick, broken
// down by endpoint/purpose, so the caller can log them without every call
// site having to track its own count. Reset at the start of each sync run
// via resetRequestCounts.
export const requestCounts = {
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
export function resetRequestCounts() {
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
 * pack-to-full placement (list 1 first) is stable across runs. Includes each
 * list's num_items straight from this same response — Cloudflare's own
 * count of its current membership — so callers can log/compare it without an
 * extra request.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} prefix
 * @returns {Promise<{id: string, name: string, numItems: number}[]>}
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
export async function getListItems(accountId, apiToken, listId) {
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
export async function addListItems(accountId, apiToken, listId, ips) {
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
 * PUT a list's full desired membership and wait for the resulting bulk
 * operation to complete. Used for the startup pull (full replace) and by
 * TEST_MODE.
 * @param {string} accountId
 * @param {string} apiToken
 * @param {string} listId
 * @param {string[]} ips - the list's full desired membership after this call
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
 * Record that IP list writes should not be attempted again for the given
 * number of hours — used after a startup pull's PUT (or the list lookup
 * before it) succeeds or fails, to pace how often a full-list PUT is tried.
 * @param {KVNamespace} kvNamespace
 * @param {number} hours
 */
export async function setIpListBackoffHours(kvNamespace, hours) {
	const until = new Date(Date.now() + hours * 60 * 60 * 1000);
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

export { MAX_ITEMS_PER_LIST };
