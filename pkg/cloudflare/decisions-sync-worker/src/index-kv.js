/**
 * CrowdSec Decisions Sync Worker — KV target
 * Periodically fetches security decisions from CrowdSec LAPI and writes them
 * to Cloudflare KV (consumed by the L7 bouncer worker).
 */

import logger from './utils/logger.js';
import { needWarmUp, markAsWarmed } from './core/decision-fetcher.js';
import { runScheduledSync } from './core/sync-runner.js';
import { processNewDecisions, processDeletedDecisions, mergeRanges, hasRangesChanged } from './core/decision-processor.js';
import {
	batchWriteStringBasedDecisions,
	batchDeleteStringBasedDecisions,
	getIpRanges,
	writeIpRanges,
	batchGetStringBasedDecisions,
	resetAllDecisionsInKV,
} from './adapters/cloudflare-kv.js';

/**
 * @param {import('./types.js').CrowdSecEnv} env
 * @returns {string | null}
 */
function validateEnv(env) {
	if (!env.CF_KV_NAMESPACE_ID) return 'CF_KV_NAMESPACE_ID environment variable is not set (required when syncing to KV)';
	return null;
}

/**
 * Sync decisions to the Worker's KV store (used by the L7 bouncer worker).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @param {boolean} needStartUpFetch
 * @returns {Promise<boolean>}
 */
async function syncToKv(env, decisions, needStartUpFetch) {
	logger.info('Starting KV sync...');

	// Mark warmed as soon as the LAPI pull itself succeeded to avoid pulling
	// the full list every time. KV is not a durable queue, so this is a
	// deliberate, accepted risk (see memory on this).
	if (needStartUpFetch) {
		await markAsWarmed(env.CROWDSECCFBOUNCERNS);
		logger.info('LAPI startup pull complete');
	}

	// Step 1: Get existing IP_RANGES from KV
	const existingRanges = await getIpRanges(env.CROWDSECCFBOUNCERNS);

	// Step 2: Check existing string decisions in KV (only on incremental updates, not first run)
	let existingStringDecisions = new Map();

	if (!needStartUpFetch) {
		// On incremental updates, check existing values to avoid redundant writes
		logger.debug('Incremental update: checking existing decisions in KV');
		const allStringKeys = [
			...decisions.new
				.filter((d) => ['ip', 'as', 'country'].includes(d.scope))
				.map((d) => (d.scope === 'country' ? d.value.toLowerCase() : d.value)),
			...decisions.deleted
				.filter((d) => ['ip', 'as', 'country'].includes(d.scope))
				.map((d) => (d.scope === 'country' ? d.value.toLowerCase() : d.value)),
		];

		// Remove duplicates
		const uniqueStringKeys = [...new Set(allStringKeys)];

		// Fetch existing string decisions from KV using bulk API
		existingStringDecisions = await batchGetStringBasedDecisions(
			env.CF_ACCOUNT_ID,
			env.CF_KV_NAMESPACE_ID,
			env.CF_API_TOKEN,
			uniqueStringKeys
		);
	} else {
		logger.debug('Startup fetch: skipping existence check (KV is empty)');
	}

	// Step 3: Process new decisions
	const newProcessed = processNewDecisions(decisions.new, existingStringDecisions, existingRanges);
	// Step 4: Process deleted decisions
	const deletedProcessed = processDeletedDecisions(decisions.deleted, existingStringDecisions, existingRanges);
	// Step 5: Merge ranges (deletions already applied in step 4, now adding new ranges)
	const finalRanges = mergeRanges(deletedProcessed.updatedRanges, newProcessed.jsonEntries);
	// Step 6: Write new/updated string decisions (IP, AS, Country) to KV using bulk API
	if (newProcessed.stringEntries.length > 0) {
		logger.info('Writing string-based decisions to KV...', { count: newProcessed.stringEntries.length });
		await batchWriteStringBasedDecisions(env.CF_ACCOUNT_ID, env.CF_KV_NAMESPACE_ID, env.CF_API_TOKEN, newProcessed.stringEntries);
	}
	// Step 7: Delete string decisions from KV using bulk API
	if (deletedProcessed.stringKeysToDelete.length > 0) {
		logger.info('Deleting string decisions from KV...', { count: deletedProcessed.stringKeysToDelete.length });
		await batchDeleteStringBasedDecisions(
			env.CF_ACCOUNT_ID,
			env.CF_KV_NAMESPACE_ID,
			env.CF_API_TOKEN,
			deletedProcessed.stringKeysToDelete
		);
	}
	// Step 8: Update IP_RANGES if changed
	if (hasRangesChanged(existingRanges, finalRanges)) {
		logger.info('IP_RANGES changed, updating KV...');
		await writeIpRanges(env.CROWDSECCFBOUNCERNS, finalRanges);
	}

	logger.info('KV sync completed successfully', {
		stringWritten: newProcessed.stringEntries.length,
		stringDeleted: deletedProcessed.stringKeysToDelete.length,
		rangesCount: Object.keys(finalRanges).length,
	});

	// Nothing above throws on a partial failure path (bulk helpers throw on
	// HTTP failure, which propagates up to runScheduledSync's catch), so
	// reaching here means the sync succeeded.
	return true;
}

/**
 * @param {ScheduledEvent} event
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {ExecutionContext} _ctx
 */
async function scheduled(event, env, _ctx) {
	await runScheduledSync(event, env, {
		validateEnv,
		needStartUpFetch: (env) => needWarmUp(env.CROWDSECCFBOUNCERNS),
		onResetRequested: async (env) => {
			logger.info('Clearing all decision keys from KV before fresh sync...');
			await resetAllDecisionsInKV(env.CF_ACCOUNT_ID, env.CF_KV_NAMESPACE_ID, env.CF_API_TOKEN, env.CROWDSECCFBOUNCERNS);
		},
		runSync: syncToKv,
	});
}

export default { scheduled };
