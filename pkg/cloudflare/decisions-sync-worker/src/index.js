/**
 * CrowdSec Autonomous Decisions Sync Worker
 * Periodically fetches security decisions from CrowdSec LAPI and updates Cloudflare KV (CROWDSECCFBOUNCERNS) storage
 */

import logger from './utils/logger.js';
import { isFirstFetch, markAsWarmed, fetchDecisionsStream } from './core/decision-fetcher.js';
import { processNewDecisions, processDeletedDecisions, mergeRanges, hasRangesChanged } from './core/decision-processor.js';
import {
	batchWriteStringBasedDecisions,
	batchDeleteStringBasedDecisions,
	getIpRanges,
	writeIpRanges,
	batchGetStringBasedDecisions,
} from './adapters/cloudflare-kv.js';

export default {
	/**
	 * Scheduled handler
	 * @param {ScheduledEvent} event - The scheduled event
	 * @param {import('./types.js').CrowdSecEnv} env - Environment bindings (secrets, KV namespaces, etc.)
	 * @param {ExecutionContext} _ctx - Execution context
	 */
	async scheduled(event, env, _ctx) {
		const startTime = Date.now();

		logger.info('Decision sync started', { cron: event.cron, scheduledTime: event.scheduledTime });

		try {
			// Validate required environment variables
			if (!env.LAPI_URL) {
				logger.error('LAPI_URL environment variable is not set');
				return;
			}

			if (!env.LAPI_KEY) {
				logger.error('LAPI_KEY secret is not set');
				return;
			}

			if (!env.CROWDSECCFBOUNCERNS) {
				logger.error('CROWDSECCFBOUNCERNS KV namespace is not bound');
				return;
			}

			const lapiUrl = env.LAPI_URL.replace(/\/$/, ''); // Remove trailing slash if present

			// Determine if this is the first fetch
			const isFirst = await isFirstFetch(env.CROWDSECCFBOUNCERNS);
			logger.info('Fetch type determined', { isFirstFetch: isFirst });

			// Parse optional filter configuration
			const scenariosContaining = env.INCLUDE_SCENARIOS ? env.INCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const scenariosNotContaining = env.EXCLUDE_SCENARIOS ? env.EXCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const origins = env.ONLY_INCLUDE_ORIGINS ? env.ONLY_INCLUDE_ORIGINS.split(',').map((s) => s.trim()) : [];

			// Fetch decisions from LAPI
			const decisions = await fetchDecisionsStream(lapiUrl, env.LAPI_KEY, {
				startup: isFirst,
				scenariosContaining,
				scenariosNotContaining,
				origins,
			});

			// Mark cache as warmed after first successful fetch
			if (isFirst) {
				await markAsWarmed(env.CROWDSECCFBOUNCERNS);
				logger.info('Cache marked as warmed after first fetch');
			}

			// Log summary
			const duration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.info('Decision stream completed successfully', {
				duration: `${duration}s`,
				newDecisions: decisions.new.length,
				deletedDecisions: decisions.deleted.length,
			});

			// ====================
			// SYNC TO KV STORE
			// ====================

			logger.info('Starting KV sync...');

			// Step 1: Get existing IP_RANGES from KV
			const existingRanges = await getIpRanges(env.CROWDSECCFBOUNCERNS);
			// Step 2: Get all string-based keys (IP, AS, Country) that we need to check
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

			// Step 3: Fetch existing string decisions from KV (batch)
			const existingStringDecisions = await batchGetStringBasedDecisions(env.CROWDSECCFBOUNCERNS, uniqueStringKeys);
			// Step 4: Process new decisions
			const newProcessed = processNewDecisions(decisions.new, existingStringDecisions, existingRanges);
			// Step 5: Process deleted decisions
			const deletedProcessed = processDeletedDecisions(decisions.deleted, existingStringDecisions, existingRanges);
			// Step 6: Merge ranges (deletions already applied in step 5, now adding new ranges)
			const finalRanges = mergeRanges(deletedProcessed.updatedRanges, newProcessed.jsonEntries);
			// Step 7: Write new/updated string decisions (IP, AS, Country) to KV
			if (newProcessed.stringEntries.length > 0) {
				logger.info('Writing string-based decisions to KV...', { count: newProcessed.stringEntries.length });
				await batchWriteStringBasedDecisions(env.CROWDSECCFBOUNCERNS, newProcessed.stringEntries);
			}
			// Step 8: Delete string decisions from KV
			if (deletedProcessed.stringKeysToDelete.length > 0) {
				logger.info('Deleting string decisions from KV...', { count: deletedProcessed.stringKeysToDelete.length });
				await batchDeleteStringBasedDecisions(env.CROWDSECCFBOUNCERNS, deletedProcessed.stringKeysToDelete);
			}
			// Step 9: Update IP_RANGES if changed
			if (hasRangesChanged(existingRanges, finalRanges)) {
				logger.info('IP_RANGES changed, updating KV...');
				await writeIpRanges(env.CROWDSECCFBOUNCERNS, finalRanges);
			}

			// Final summary
			const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);

			logger.info('KV sync completed successfully', {
				totalDuration: `${finalDuration}s`,
				stringWritten: newProcessed.stringEntries.length,
				stringDeleted: deletedProcessed.stringKeysToDelete.length,
				rangesCount: Object.keys(finalRanges).length,
			});
		} catch (error) {
			const duration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.error('Decision sync failed', {
				duration: `${duration}s`,
				error: error.message,
				stack: error.stack,
			});

			// Don't throw - we want to continue running on the next cron trigger
			// The existing decisions in KV (if any) will remain valid
		}
	},
};
