/**
 * Cloudflare KV Adapter
 * Handles batch read/write/delete operations for Cloudflare KV store
 */

import logger from '../utils/logger.js';

const BATCH_SIZE = 10000; // Cloudflare KV limit for batch operations
const IP_RANGES_KEY = 'IP_RANGES';

/**
 * Write decisions to KV in batches
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @param {import('../types.js').KVEntry[]} entries - Entries to write
 * @returns {Promise<number>} Number of entries written
 */
export async function batchWriteStringBasedDecisions(kvNamespace, entries) {
	if (!entries || entries.length === 0) {
		logger.debug('No entries to write to KV');
		return 0;
	}

	let written = 0;

	// Process in batches of BATCH_SIZE
	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(entries.length / BATCH_SIZE);

		logger.debug(`Writing batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalEntries: entries.length,
		});

		// Write each entry in the batch
		const promises = batch.map((entry) => kvNamespace.put(entry.key, entry.value));

		await Promise.all(promises);
		written += batch.length;

		logger.debug(`Batch ${batchNum}/${totalBatches} written successfully`);
	}

	return written;
}

/**
 * Delete decisions from KV in batches
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @param {string[]} keys - Keys to delete
 * @returns {Promise<number>} Number of entries deleted
 */
export async function batchDeleteStringBasedDecisions(kvNamespace, keys) {
	if (!keys || keys.length === 0) {
		logger.debug('No keys to delete from KV');
		return 0;
	}

	let deleted = 0;

	// Process in batches of BATCH_SIZE
	for (let i = 0; i < keys.length; i += BATCH_SIZE) {
		const batch = keys.slice(i, i + BATCH_SIZE);
		const batchNum = Math.floor(i / BATCH_SIZE) + 1;
		const totalBatches = Math.ceil(keys.length / BATCH_SIZE);

		logger.debug(`Deleting batch ${batchNum}/${totalBatches}`, {
			batchSize: batch.length,
			totalKeys: keys.length,
		});

		// Delete each key in the batch
		const promises = batch.map((key) => kvNamespace.delete(key));

		await Promise.all(promises);
		deleted += batch.length;

		logger.debug(`Batch ${batchNum}/${totalBatches} deleted successfully`);
	}

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
 * Get multiple keys from KV (for checking existing decisions)
 * Note: KV doesn't have a native batch get, so we do individual gets in parallel
 * @param {KVNamespace} kvNamespace - Cloudflare KV namespace
 * @param {string[]} keys - Keys to fetch
 * @returns {Promise<Map<string, string>>} Map of key -> value for existing entries
 */
export async function batchGetStringBasedDecisions(kvNamespace, keys) {
	if (!keys || keys.length === 0) {
		return new Map();
	}

	logger.debug(`Fetching ${keys.length} keys (ip, as or country) from KV`);

	// Fetch all keys in parallel
	const promises = keys.map(async (key) => {
		const value = await kvNamespace.get(key);
		return { key, value };
	});

	const results = await Promise.all(promises);

	// Build map of existing entries
	const existingMap = new Map();
	for (const { key, value } of results) {
		if (value !== null) {
			existingMap.set(key, value);
		}
	}

	logger.debug(`Found ${existingMap.size} existing entries in KV out of ${keys.length} requested`);

	return existingMap;
}
