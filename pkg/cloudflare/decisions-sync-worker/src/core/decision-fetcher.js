/**
 * CrowdSec LAPI Decision Fetcher
 * Fetches security decisions from CrowdSec LAPI or BLaaS endpoint
 * Based on the Node.js bouncer implementation pattern
 */

import logger from '../utils/logger.js';

const USER_AGENT = 'cloudflare-worker-bouncer/v1.0.0';
const WARMED_UP_KEY = 'WARMED_UP';
const SUPPORTED_SCOPES = ['ip', 'range', 'as', 'country'];

/**
 * Check if this is the first fetch by looking for the WARMED_UP flag in KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<boolean>} True if this is the first fetch
 */
export async function isFirstFetch(kvNamespace) {
	const warmedUpFlag = await kvNamespace.get(WARMED_UP_KEY);
	return !warmedUpFlag;
}

/**
 * Mark the cache as warmed up (first fetch completed)
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 */
export async function markAsWarmed(kvNamespace) {
	await kvNamespace.put(WARMED_UP_KEY, 'true');
	logger.debug('Cache marked as warmed');
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
export async function fetchDecisionsStream(lapiUrl, apiKey, options = {}) {
	const params = buildQueryParams(options);
	const fullUrl = `${lapiUrl}/v1/decisions/stream?${params.toString()}`;

	logger.debug('Fetching decisions from LAPI', { url: fullUrl, startup: options.startup });

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

	// Handle HTTP 204 No Content (LAPI has no decisions - need to delete all from KV)
	if (response.status === 204) {
		logger.info('LAPI returned 204 No Content: LAPI has no decisions, will clear KV');
		return {
			new: [],
			deleted: [],
			deleteAll: true, // Signal to main sync logic to reset KV and exit
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
