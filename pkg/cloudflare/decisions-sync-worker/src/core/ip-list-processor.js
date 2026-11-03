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
export function filterIpListScopes(decisions) {
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
export function planUpserts(newDecisions, expiredDecisions, warn) {
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
 * the room each list has available. A list already at capacity is
 * skipped entirely. Items that don't fit anywhere are left un-planned
 * (still 'new' in the queue, retried next tick).
 * @param {{ip: string, action: string, until: string}[]} pendingAdds
 * @param {string[]} listIds - managed list ids, in stable (name-sorted) order
 * @param {Map<string, number>} listSizes - list_id -> available room (current size, net of this tick's pending deletes)
 * @param {number} maxItemsPerList
 * @returns {{addsByList: Map<string, {ip: string, action: string, until: string}[]>, unplaced: string[]}}
 */
export function planAdds(pendingAdds, listIds, listSizes, maxItemsPerList) {
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
