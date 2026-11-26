/**
 * IP List Reconciler
 * Pure diff computation for a full re-sync of a Cloudflare IP List against
 * the complete set of currently-active LAPI decisions (a "startup" pull,
 * not an incremental new/deleted delta). Unlike syncToIpListStartup's PUT
 * (which blindly replaces the list's entire contents), this compares the
 * desired set against what's actually in the list and returns only the
 * difference — meant for a periodic reconciliation pass that corrects any
 * drift (missed adds/removes, manual edits, ...) without the cost/risk of a
 * full replace.
 *
 * No network calls here and no Workers-specific API — this only takes
 * plain data in and returns plain data out, so it can run identically
 * inside the Worker or in a local Node benchmark script.
 */

/**
 * Compute the add/remove diff between the desired IP set (from a full LAPI
 * startup pull) and a list's current membership.
 * @param {string[]} desiredIps - every ip/range value that should be in the
 *   list right now (e.g. from filterIpListScopes(decisions.new).map(d => d.value)
 *   on a startup=true LAPI response); duplicates are tolerated
 * @param {Map<string, string>} currentItems - the list's current membership,
 *   as returned by getListItems: ip -> Cloudflare item id
 * @returns {{ toAdd: string[], toRemove: string[] }} toAdd are desired IPs
 *   missing from the list; toRemove are the current items' ids whose IP is
 *   no longer desired
 */
export function diffIpList(desiredIps, currentItems) {
	const desired = new Set(desiredIps);

	const toAdd = [];
	for (const ip of desired) {
		if (!currentItems.has(ip)) {
			toAdd.push(ip);
		}
	}

	const toRemove = [];
	for (const [ip, id] of currentItems) {
		if (!desired.has(ip)) {
			toRemove.push(id);
		}
	}

	return { toAdd, toRemove };
}
