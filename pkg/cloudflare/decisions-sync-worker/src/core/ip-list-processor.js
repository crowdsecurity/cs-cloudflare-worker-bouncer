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

import { MAX_ITEMS_PER_LIST } from '../adapters/cloudflare-ip-lists.js';

const IP_LIST_SCOPES = ['ip', 'range'];

/**
 * Filter a decision batch down to the scopes an IP List can represent.
 * @param {import('../types.js').Decision[]} decisions
 * @returns {import('../types.js').Decision[]}
 */
export function filterIpListScopes(decisions) {
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
export function planQueueUpserts(decisions, index, isExpiry) {
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
export function splitBatch(batch, index) {
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
export function planAdds(newRows, listNames, index) {
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
