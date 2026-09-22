/**
 * CrowdSec Autonomous Decisions Sync Worker
 * Periodically fetches security decisions from CrowdSec LAPI and updates
 * exactly one sync target: Cloudflare KV (SYNC_TO_LIST_NOT_KV=false, the
 * default) or Cloudflare IP Lists (SYNC_TO_LIST_NOT_KV=true).
 */

import logger from './utils/logger.js';
import {
	needWarmUp,
	markAsWarmed,
	fetchDecisionsStream,
	tryAcquireSyncLock,
	releaseSyncLock,
} from './core/decision-fetcher.js';
import { processNewDecisions, processDeletedDecisions, mergeRanges, hasRangesChanged } from './core/decision-processor.js';
import {
	batchWriteStringBasedDecisions,
	batchDeleteStringBasedDecisions,
	getIpRanges,
	writeIpRanges,
	batchGetStringBasedDecisions,
	shouldReset,
	resetAllDecisions,
	clearResetFlag,
} from './adapters/cloudflare-kv.js';
import { planUpserts, planAdds } from './core/ip-list-processor.js';
import {
	listManagedIpLists,
	upsertDeletes,
	upsertNews,
	readPendingDeletes,
	readPendingAdds,
	readListSizes,
	readAllListed,
	markListed,
	deleteQueueRows,
	clearQueue,
	addListItems,
	removeListItems,
	getBackoffUntil,
	setBackoff,
	clearBackoff,
	MAX_ITEMS_PER_LIST,
	CloudflareApiError,
} from './adapters/cloudflare-ip-lists.js';

const DEFAULT_IP_LIST_PREFIX = 'crowdsec_';
const DEFAULT_IP_LIST_BATCH_SIZE = 1000;

/**
 * Scheduled handler
 * @param {ScheduledEvent} event - The scheduled event
 * @param {import('./types.js').CrowdSecEnv} env - Environment bindings (secrets, KV namespaces, etc.)
 * @param {ExecutionContext} _ctx - Execution context
 */
async function scheduled(event, env, _ctx) {
	const startTime = Date.now();

	logger.info('Decision sync started', { cron: event.cron, scheduledTime: event.scheduledTime });

	try {
		// By Default, the worker syncs to KV unless explicitly configured to sync to IP Lists (SYNC_TO_LIST_NOT_KV=true).
		const syncToListsMode = env.SYNC_TO_LIST_NOT_KV === 'true';
		// Logic variables to make code more readable along the way
		const syncToKvEnabled = !syncToListsMode;
		const syncToIpListsEnabled = syncToListsMode;

		// Validate required environment variables
		if (!env.LAPI_URL) {
			logger.error('LAPI_URL environment variable is not set');
			return;
		}

		if (!env.LAPI_KEY) {
			logger.error('LAPI_KEY secret is not set');
			return;
		}

		// CROWDSECCFBOUNCERNS is required in both modes: KV or IP Lists.
		if (!env.CROWDSECCFBOUNCERNS) {
			logger.error('CROWDSECCFBOUNCERNS KV namespace is not bound');
			return;
		}

		if (!env.CF_ACCOUNT_ID) {
			logger.error('CF_ACCOUNT_ID environment variable is not set');
			return;
		}

		// CF_KV_NAMESPACE_ID is only used for bulk KV API calls
		if (syncToKvEnabled && !env.CF_KV_NAMESPACE_ID) {
			logger.error('CF_KV_NAMESPACE_ID environment variable is not set (required when syncing to KV)');
			return;
		}

		if (syncToIpListsEnabled && !env.LIST_STATE_DB) {
			logger.error('LIST_STATE_DB D1 database is not bound (required when syncing to IP Lists)');
			return;
		}

		if (!env.CF_API_TOKEN) {
			logger.error('CF_API_TOKEN secret is not set (required for bulk KV/IP list operations)');
			return;
		}

		const lapiUrl = env.LAPI_URL.replace(/\/$/, ''); // Remove trailing slash if present

		// Lock to avoid overlapping syncs from multiple cron ticks or manual runs.
		const lockAcquired = await tryAcquireSyncLock(env.CROWDSECCFBOUNCERNS);
		if (!lockAcquired) {
			logger.info('Sync already in progress, skipping this run');
			return;
		}

		try {
			// Determine if this is the first fetch
			const needStartUpFetch = await needWarmUp(env.CROWDSECCFBOUNCERNS);
			logger.info('Pull All decisions ?', { startup: needStartUpFetch });

			// Check if reset is requested
			const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);

			// Clear residual decisions before a fresh pull or on an explicit RESET
			if ((resetRequested || needStartUpFetch) && syncToKvEnabled) {
				logger.info('Clearing all decision keys from KV before fresh sync...');
				await resetAllDecisions(
					env.CF_ACCOUNT_ID,
					env.CF_KV_NAMESPACE_ID,
					env.CF_API_TOKEN,
					env.CROWDSECCFBOUNCERNS
				);
			}
			if ((resetRequested || needStartUpFetch) && syncToIpListsEnabled) {
				logger.info('Clearing all managed IP lists and the sync queue before fresh sync...');
				await clearAllIpLists(env);
			}

			if (resetRequested) {
				await clearResetFlag(env.CROWDSECCFBOUNCERNS);
			}

			// Parse optional filter configuration
			const scenariosContaining = env.INCLUDE_SCENARIOS ? env.INCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const scenariosNotContaining = env.EXCLUDE_SCENARIOS ? env.EXCLUDE_SCENARIOS.split(',').map((s) => s.trim()) : [];
			const origins = env.ONLY_INCLUDE_ORIGINS ? env.ONLY_INCLUDE_ORIGINS.split(',').map((s) => s.trim()) : [];

			// Fetch decisions from LAPI
			const decisions = await fetchDecisionsStream(lapiUrl, env.LAPI_KEY, {
				startup: needStartUpFetch,
				scenariosContaining,
				scenariosNotContaining,
				origins,
			});

			// Log summary
			const duration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.info('Decision stream completed successfully', {
				duration: `${duration}s`,
				newDecisions: decisions.new.length,
				deletedDecisions: decisions.deleted.length,
			});

			// Handle HTTP 204 (LAPI has no decisions - clear the active sync target)
			if (decisions.deleteAll) {
				if (syncToKvEnabled) {
					logger.info('LAPI has no decisions (204): clearing all decision keys from KV...');
					await resetAllDecisions(
						env.CF_ACCOUNT_ID,
						env.CF_KV_NAMESPACE_ID,
						env.CF_API_TOKEN,
						env.CROWDSECCFBOUNCERNS
					);
				}
				if (syncToIpListsEnabled) {
					await clearAllIpLists(env);
				}
				// Safe to mark warmed here: it it's empty state we want
				if (needStartUpFetch) {
					await markAsWarmed(env.CROWDSECCFBOUNCERNS);
					logger.info('Cache marked as warmed (LAPI has no decisions)');
				}
				const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
				logger.info('Cleared successfully (LAPI has no decisions)', {
					totalDuration: `${finalDuration}s`,
				});
				return; // Exit early - no further sync needed
			}

			let syncSucceeded;
			if (syncToKvEnabled) {
				await syncToKv(env, decisions, needStartUpFetch);
				// syncToKv throws on failure, so reaching this point means it succeeded
				syncSucceeded = true;
			} else {
				// Partial sync possible: in D1 but not in lists yet
				syncSucceeded = await syncToIpLists(env, decisions);
			}

			// Mark cache as warmed ONLY after the sync target has captured
			// this run's decisions. If this runs before every write actually
			// landed, a mid-sync crash leaves WARMED_UP=true with some
			// decisions never applied, and the next run does an incremental
			// fetch that never backfills what was missed — a silent
			// enforcement gap.
			if (needStartUpFetch && syncSucceeded) {
				await markAsWarmed(env.CROWDSECCFBOUNCERNS);
				logger.info('Cache marked as warmed (first sync complete)');
			} else if (needStartUpFetch) {
				logger.warn('First sync incomplete (IP list sync failed); cache not marked as warmed yet');
			}

			// Final summary
			const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
			logger.info('Decision sync completed successfully', { totalDuration: `${finalDuration}s` });
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

		// Don't throw - we want to continue running on the next cron trigger
		// The existing decisions in KV (if any) will remain valid
	}
}

/**
 * Sync decisions to the Worker's KV store (used by the L7 bouncer worker).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @param {boolean} needStartUpFetch
 */
async function syncToKv(env, decisions, needStartUpFetch) {
	logger.info('Starting KV sync...');

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
}

/**
 * Sync decisions to Cloudflare IP Lists (used for L3/4 bouncing). 
 *
 * The D1 table is the source of truth for pending work and current list content index
 *
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>} true unless this tick stopped early (rate
 *   limit or error) — an unplaced/still-pending remainder is normal,
 *   expected progress, not a failure.
 */
async function syncToIpLists(env, decisions) {
	logger.info('Starting IP list sync...');

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const batchSize = env.IP_LIST_BATCH_SIZE ? parseInt(env.IP_LIST_BATCH_SIZE, 10) : DEFAULT_IP_LIST_BATCH_SIZE;
	const db = env.LIST_STATE_DB;

	// Split into upsert-ready entries, warning if the same IP shows up (delete always wins).
	const { newItems, deleteItems } = planUpserts(decisions.new, decisions.deleted, (msg, ctx) => logger.warn(msg, ctx));

	// Upsert new decisions (list_action='new' unless already 'listed'),
	await upsertNews(db, newItems);
	// then expired decisions (list_action='delete', unconditionally)
	await upsertDeletes(db, deleteItems);

	// Check if we're currently backing off due to a previous rate limit.
	const backoffUntil = await getBackoffUntil(env.CROWDSECCFBOUNCERNS);
	if (backoffUntil && backoffUntil > new Date()) {
		logger.warn('Skipping Cloudflare IP list updates: backing off after a previous rate limit', {
			backoffUntil: backoffUntil.toISOString(),
		});
		
		return false;
	}

	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	if (lists.length === 0) {
		logger.warn(`No IP Lists found with prefix "${prefix}"; skipping IP list sync`);
		// Nothing we can do without any managed lists; don't block warming on it.
		return true;
	}
	const listNameById = new Map(lists.map((l) => [l.id, l.name]));
	const listIds = lists.map((l) => l.id); // already name-sorted by listManagedIpLists

	// Apply every pending delete now — removals aren't paced/batched like
	// adds are, since getting a ban off a list promptly matters more than
	// pacing removals.
	const { deletesByList, queueOnlyDeletes } = await readPendingDeletes(db);
	const confirmedIps = new Set(queueOnlyDeletes); // IP not in Lists yet, only remove from D1

	// Per-list tallies for the completion summary below, so it's clear at a
	// glance which lists were actually touched this tick and by how much.
	const updatedLists = new Map(); // listName -> { added, removed }
	const bumpListStat = (listName, key, n) => {
		const stat = updatedLists.get(listName) || { added: 0, removed: 0 };
		stat[key] += n;
		updatedLists.set(listName, stat);
	};

	let removedCount = 0;
	try {
		for (const [listId, toDelete] of deletesByList) {
			const listName = listNameById.get(listId) ?? listId;
			logger.info(`Removing ${toDelete.length} item(s) from IP list ${listName}...`, {
				list: listName,
				removed: toDelete.length,
			});
			try {
				await removeListItems(
					env.CF_ACCOUNT_ID,
					env.CF_API_TOKEN,
					listId,
					toDelete.map((t) => t.itemId)
				);
			} catch (e) {
				return handleIpListError(env, e, `removing items from IP list ${listName}`);
			}
			for (const { ip } of toDelete) {
				confirmedIps.add(ip);
				removedCount++;
			}
			bumpListStat(listName, 'removed', toDelete.length);
		}
	} finally {
		// Rows Cloudflare confirmed removed, or that were never actually pushed,
		// are done for good — drop them from the table entirely. Runs whether
		// the loop above completed or bailed out early on an API error, so
		// confirmed rows never get stuck in the table waiting for next tick.
		await deleteQueueRows(db, [...confirmedIps]);
	}

	// 5: place a bounded batch of pending adds, packing lists to capacity in
	// order based on current member counts.
	const pendingAdds = await readPendingAdds(db, batchSize);
	let addedCount = 0;
	let unplacedCount = 0;

	if (pendingAdds.length > 0) {
		const listSizes = await readListSizes(db);
		const { addsByList, unplaced } = planAdds(pendingAdds, listIds, listSizes, MAX_ITEMS_PER_LIST);
		unplacedCount = unplaced.length;
		if (unplaced.length > 0) {
			logger.warn(`${unplaced.length} pending IP(s) have no room in any managed list; left pending`);
		}

		for (const [listId, items] of addsByList) {
			const listName = listNameById.get(listId) ?? listId;
			const ips = items.map((i) => i.ip);
			logger.info(`Adding ${ips.length} item(s) to IP list ${listName}...`, {
				list: listName,
				added: ips.length,
			});

			let itemIdByIp;
			try {
				itemIdByIp = await addListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, listId, ips);
			} catch (e) {
				// Deletes and any earlier add iterations already committed above
				// (and via markListed calls below) stay applied; the rest of this
				// tick's adds stay pending for next time.
				return handleIpListError(env, e, `adding items to IP list ${listName}`);
			}

			const placed = items.map((item) => ({ ip: item.ip, itemId: itemIdByIp.get(item.ip) })).filter((p) => p.itemId);
			await markListed(db, listId, placed);
			addedCount += placed.length;
			bumpListStat(listName, 'added', placed.length);
		}
	}

	// Made it through this tick without hitting a rate limit; clear any
	// stale backoff from a previous run so the next tick isn't held back
	// unnecessarily.
	await clearBackoff(env.CROWDSECCFBOUNCERNS);

	logger.info('IP list sync completed successfully', {
		removed: removedCount,
		added: addedCount,
		listsUpdated: [...updatedLists.entries()].map(([list, stat]) => ({ list, ...stat })),
		unplaced: unplacedCount,
	});

	return true;
}

/**
 * Shared handling for a failed IP list mutation: distinguish a rate limit
 * (which we can back off for a known duration) from anything else (which we
 * can't reliably identify, so we just stop and retry next tick).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {unknown} e
 * @param {string} what - human-readable description of the failed operation
 * @returns {Promise<false>}
 */
async function handleIpListError(env, e, what) {
	if (e instanceof CloudflareApiError && e.status === 429 && e.retryAfterSeconds !== undefined) {
		logger.warn(`Rate limited ${what}; backing off`, { retryAfterSeconds: e.retryAfterSeconds });
		await setBackoff(env.CROWDSECCFBOUNCERNS, e.retryAfterSeconds);
	} else {
		// Anything else (quota exceeded, malformed request, transient 5xx,
		// ...) — Cloudflare doesn't give us a reliable way to tell these apart
		// from the response alone, so stop for this run and retry next sync
		// rather than risk cascading failures.
		logger.error(`Failed ${what}; stopping IP list sync for this run`, {
			error: e instanceof Error ? e.message : String(e),
			status: e instanceof CloudflareApiError ? e.status : undefined,
			body: e instanceof CloudflareApiError ? e.body : undefined,
		});
	}
	return false;
}

/**
 * Empty every managed IP list and the D1 table entirely. Used when LAPI
 * reports no decisions at all (HTTP 204), mirroring the KV path's
 * resetAllDecisions.
 * @param {import('./types.js').CrowdSecEnv} env
 */
async function clearAllIpLists(env) {
	logger.info('Clearing all managed IP lists...');

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const db = env.LIST_STATE_DB;
	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	const listNameById = new Map(lists.map((l) => [l.id, l.name]));
	const listedByList = await readAllListed(db);

	const clearedLists = [];
	for (const [listId, members] of listedByList) {
		if (members.length === 0) continue;
		const listName = listNameById.get(listId) ?? listId;

		logger.info(`Emptying IP list ${listName}...`, { list: listName, removed: members.length });
		await removeListItems(
			env.CF_ACCOUNT_ID,
			env.CF_API_TOKEN,
			listId,
			members.map((m) => m.itemId)
		);
		clearedLists.push({ list: listName, removed: members.length });
	}

	await clearQueue(db);

	logger.info('All managed IP lists cleared successfully', { listCount: lists.length, listsUpdated: clearedLists });
}

export default { scheduled };
