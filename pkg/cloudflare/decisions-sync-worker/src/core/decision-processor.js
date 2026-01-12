/**
 * Decision Processor
 * Processes CrowdSec decisions and prepares them for KV storage
 */

import logger from '../utils/logger.js';

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
export function processNewDecisions(decisions, existingStringDecisions, existingRanges) {
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
export function processDeletedDecisions(decisions, existingStringDecisions, existingRanges) {
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
export function mergeRanges(baseRanges, additionalRanges) {
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
export function hasRangesChanged(oldRanges, newRanges) {
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
