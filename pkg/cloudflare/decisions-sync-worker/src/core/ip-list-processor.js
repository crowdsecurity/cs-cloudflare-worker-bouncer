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
export function filterIpListScopes(decisions) {
	return decisions.filter((d) => IP_LIST_SCOPES.includes(d.scope));
}
