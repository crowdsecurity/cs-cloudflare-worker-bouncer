/**
 * Shared scheduled-tick skeleton for both decisions-sync workers (KV and IP
 * Lists). Each worker is a separate compiled script with exactly one sync
 * target, chosen at deploy time rather than by a runtime flag — this module
 * holds everything that's identical either way: env validation, the sync
 * lock, the LAPI pull, and RESET/WARMED_UP handling. The target-specific sync
 * itself is supplied by the caller as `runSync`.
 */

import logger from '../utils/logger.js';
import { fetchDecisionsStream, tryAcquireSyncLock, releaseSyncLock, shouldReset, clearResetFlag } from './decision-fetcher.js';

/**
 * @param {import('../types.js').CrowdSecEnv} env
 * @returns {string | null} an error message if validation fails, else null
 */
function validateCommonEnv(env) {
	if (!env.LAPI_URL) return 'LAPI_URL environment variable is not set';
	if (!env.LAPI_KEY) return 'LAPI_KEY secret is not set';
	if (!env.CROWDSECCFBOUNCERNS) return 'CROWDSECCFBOUNCERNS KV namespace is not bound';
	if (!env.CF_ACCOUNT_ID) return 'CF_ACCOUNT_ID environment variable is not set';
	if (!env.CF_API_TOKEN) return 'CF_API_TOKEN secret is not set (required for bulk KV/IP list operations)';
	return null;
}

/**
 * @typedef {Object} SyncHooks
 * @property {(env: import('../types.js').CrowdSecEnv) => string | null} [validateEnv] - extra env validation beyond validateCommonEnv
 * @property {(env: import('../types.js').CrowdSecEnv) => Promise<boolean>} [shouldSkip] - checked right after the lock is acquired, before any LAPI pull; returning true no-ops the entire tick (e.g. waiting out a backoff)
 * @property {(env: import('../types.js').CrowdSecEnv) => Promise<boolean>} needStartUpFetch - whether this tick must be a full LAPI pull
 * @property {(env: import('../types.js').CrowdSecEnv, resetRequested: boolean) => Promise<void>} [onResetRequested] - called once, before the LAPI pull, when RESET was requested
 * @property {(env: import('../types.js').CrowdSecEnv, decisions: import('../types.js').DecisionStreamResponse, needStartUpFetch: boolean) => Promise<boolean>} runSync - performs the actual sync, returns whether it succeeded
 */

/**
 * Run one scheduled tick: validate env, acquire the sync lock, pull decisions
 * from LAPI, run the target-specific sync, release the lock. Swallows all
 * errors (logged, not rethrown) so a failed tick never surfaces as an
 * unhandled Worker exception.
 * @param {ScheduledEvent} event
 * @param {import('../types.js').CrowdSecEnv} env
 * @param {SyncHooks} hooks
 */
export async function runScheduledSync(event, env, hooks) {
	const startTime = Date.now();

	logger.info('Decision sync started', { cron: event.cron, scheduledTime: event.scheduledTime });

	try {
		const commonError = validateCommonEnv(env);
		if (commonError) {
			logger.error(commonError);
			return;
		}
		if (hooks.validateEnv) {
			const specificError = hooks.validateEnv(env);
			if (specificError) {
				logger.error(specificError);
				return;
			}
		}

		const lapiUrl = env.LAPI_URL.replace(/\/$/, ''); // Remove trailing slash if present

		// Lock to avoid overlapping syncs from multiple cron ticks or manual runs.
		const lockAcquired = await tryAcquireSyncLock(env.CROWDSECCFBOUNCERNS);
		if (!lockAcquired) {
			logger.info('Sync already in progress, skipping this run');
			return;
		}

		try {
			if (hooks.shouldSkip && (await hooks.shouldSkip(env))) {
				return;
			}

			const needStartUpFetch = await hooks.needStartUpFetch(env);
			logger.info('Determined fetch mode', { startup: needStartUpFetch });

			const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);
			if (resetRequested && hooks.onResetRequested) {
				await hooks.onResetRequested(env, resetRequested);
			}
			if (resetRequested) {
				await clearResetFlag(env.CROWDSECCFBOUNCERNS);
			}

			// Parse optional filter configuration
			const scenariosContaining = env.INCLUDE_SCENARIOS ? env.INCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const scenariosNotContaining = env.EXCLUDE_SCENARIOS ? env.EXCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const origins = env.ONLY_INCLUDE_ORIGINS ? env.ONLY_INCLUDE_ORIGINS.split(',').map((s) => s.trim()) : [];

			const decisions = await fetchDecisionsStream(lapiUrl, env.LAPI_KEY, {
				startup: needStartUpFetch,
				scenariosContaining,
				scenariosNotContaining,
				origins,
			});

			const duration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.info('Decision stream completed successfully', {
				duration: `${duration}s`,
				newDecisions: decisions.new.length,
				deletedDecisions: decisions.deleted.length,
			});

			const syncSucceeded = await hooks.runSync(env, decisions, needStartUpFetch);

			const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
			if (syncSucceeded) {
				logger.info('Decision sync tick finished', { totalDuration: `${finalDuration}s`, syncSucceeded });
			} else {
				logger.warn('Decision sync tick finished without syncing (see warnings above for why)', {
					totalDuration: `${finalDuration}s`,
					syncSucceeded,
				});
			}
		} finally {
			await releaseSyncLock(env.CROWDSECCFBOUNCERNS);
		}
	} catch (error) {
		const duration = ((Date.now() - startTime) / 1000).toFixed(2);
		logger.error('Decision sync failed', {
			duration: `${duration}s`,
			error: error.message,
			stack: error.stack,
		});

		// Swallow the error rather than rethrow
		// No advantage throwing + we have enough logs to find out what happened
	}
}
