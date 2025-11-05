/**
 * Cloudflare KV Adapter
 * Handles batch read/write/delete operations for Cloudflare KV store
 * Uses Cloudflare REST API bulk endpoints to minimize operation count
 */

import logger from '../utils/logger.js';

const BATCH_SIZE = 10000; // Cloudflare KV limit for bulk operations
const IP_RANGES_KEY = 'IP_RANGES';

/**
 * Build headers for Cloudflare API requests
 * @param {string} apiToken - Cloudflare API token
 * @returns {Object} Headers object
 */
function buildApiHeaders(apiToken) {
	return {
		'Authorization': `Bearer ${apiToken}`,
		'Content-Type': 'application/json',
	};
}

/**
 * Write decisions to KV using bulk API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {import('../types.js').KVEntry[]} entries - Entries to write
 * @returns {Promise<number>} Number of entries written
 */
export async function batchWriteStringBasedDecisions(accountId, namespaceId, apiToken, entries) {
	if (!entries || entries.length === 0) {
		logger.debug('No entries to write to KV');
		return 0;
	}

	let written = 0;

	logger.debug(`Writing ${entries.length} entries to KV using bulk API`);

	// Process in batches of BATCH_SIZE (10,000 max per bulk request)
	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(entries.length / BATCH_SIZE);

		logger.debug(`Writing bulk batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalEntries: entries.length,
		});

		const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/bulk`;

		const response = await fetch(url, {
			method: 'PUT',
			headers: buildApiHeaders(apiToken),
			body: JSON.stringify(batch),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Bulk write failed (batch ${batchNum}): ${response.status} ${errorText}`);
		}

		written += batch.length;
		logger.debug(`Bulk batch ${batchNum}/${totalBatches} written successfully`);
	}

	logger.debug(`Wrote ${written} entries to KV successfully`);

	return written;
}

/**
 * Delete decisions from KV using bulk API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {string[]} keys - Keys to delete
 * @returns {Promise<number>} Number of entries deleted
 */
export async function batchDeleteStringBasedDecisions(accountId, namespaceId, apiToken, keys) {
	if (!keys || keys.length === 0) {
		logger.debug('No keys to delete from KV');
		return 0;
	}

	let deleted = 0;

	logger.debug(`Deleting ${keys.length} keys from KV using bulk API`);

	// Process in batches of BATCH_SIZE (10,000 max per bulk request)
	for (let i = 0; i < keys.length; i += BATCH_SIZE) {
		const batch = keys.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(keys.length / BATCH_SIZE);

		logger.debug(`Deleting bulk batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalKeys: keys.length,
		});

		const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/bulk`;

		const response = await fetch(url, {
			method: 'DELETE',
			headers: buildApiHeaders(apiToken),
			body: JSON.stringify(batch),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Bulk delete failed (batch ${batchNum}): ${response.status} ${errorText}`);
		}

		deleted += batch.length;
		logger.debug(`Bulk batch ${batchNum}/${totalBatches} deleted successfully`);
	}

	logger.debug(`Deleted ${deleted} keys from KV successfully`);

	return deleted;
}

/**
 * Get the current IP_RANGES object from KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @returns {Promise<import('../types.js').IpRanges>} IP ranges object (CIDR -> remediation)
 */
export async function getIpRanges(kvNamespace) {
	try {
		const rangesJson = await kvNamespace.get(IP_RANGES_KEY);
		if (!rangesJson) {
			logger.debug('No IP_RANGES found in KV, returning empty object');
			return {};
		}

		const ranges = JSON.parse(rangesJson);
		logger.debug('Fetched IP_RANGES from KV', { count: Object.keys(ranges).length });
		return ranges;
	} catch (error) {
		logger.error('Failed to parse IP_RANGES from KV', { error: error.message });
		return {};
	}
}

/**
 * Write the IP_RANGES object to KV
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @param {import('../types.js').IpRanges} ranges - IP ranges object (CIDR -> remediation)
 * @returns {Promise<void>}
 */
export async function writeIpRanges(kvNamespace, ranges) {
	const rangesJson = JSON.stringify(ranges);
	await kvNamespace.put(IP_RANGES_KEY, rangesJson);
}

/**
 * Get multiple keys from KV using bulk API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} namespaceId - KV namespace ID
 * @param {string} apiToken - Cloudflare API token
 * @param {string[]} keys - Keys to fetch
 * @returns {Promise<Map<string, string>>} Map of key -> value for existing entries
 */
export async function batchGetStringBasedDecisions(accountId, namespaceId, apiToken, keys) {
	if (!keys || keys.length === 0) {
		return new Map();
	}

	logger.debug(`Fetching ${keys.length} keys (ip, as or country) from KV using bulk API`);

	const existingMap = new Map();

	// Process in batches of BATCH_SIZE (10,000 max per bulk request)
	for (let i = 0; i < keys.length; i += BATCH_SIZE) {
		const batch = keys.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(keys.length / BATCH_SIZE);

		logger.debug(`Fetching bulk batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalKeys: keys.length,
		});

		const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values`;

		const response = await fetch(url, {
			method: 'POST',
			headers: buildApiHeaders(apiToken),
			body: JSON.stringify(batch),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Bulk get failed (batch ${batchNum}): ${response.status} ${errorText}`);
		}

		const results = await response.json();

		// Build map of existing entries
		// API returns array of {key, value} objects
		for (const item of results) {
			if (item.value !== null) {
				existingMap.set(item.key, item.value);
			}
		}

		logger.debug(`Bulk batch ${batchNum}/${totalBatches} fetched successfully`);
	}

	logger.debug(`Found ${existingMap.size} existing entries in KV out of ${keys.length} requested`);

	return existingMap;
}
