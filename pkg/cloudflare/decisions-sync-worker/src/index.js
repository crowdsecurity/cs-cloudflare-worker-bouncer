/**
 * CrowdSec Autonomous Decisions Sync Worker
 * Periodically fetches security decisions from CrowdSec LAPI and updates Cloudflare KV (CROWDSECCFBOUNCERNS) storage
 */

import logger from './utils/logger.js';
import {
	isFirstFetch,
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
 * Sync decisions to the Worker's KV store (used by the L7 bouncer worker).
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @param {boolean} isFirst
 */
async function syncToKv(env, decisions, isFirst) {
	logger.info('Starting KV sync...');

	// Step 1: Get existing IP_RANGES from KV
	const existingRanges = await getIpRanges(env.CROWDSECCFBOUNCERNS);

	// Step 2: Check existing string decisions in KV (only on incremental updates, not first run)
	let existingStringDecisions = new Map();

	if (!isFirst) {
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
		logger.debug('First run: skipping existence check (KV is empty)');
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
 * Sync decisions to Cloudflare IP Lists (used for L3/4 bouncing). List
 * creation and the firewall rules referencing these lists are provisioned
 * externally — this only fills/empties membership of lists whose name
 * starts with IP_LIST_PREFIX.
 *
 * The D1 table (env.CROWDSECCFBOUNCER_QUEUE_DB) is the single source of
 * truth for both pending work and current membership — see
 * cloudflare-ip-lists.js for the row shape. Each tick: expired decisions are
 * upserted as list_action='delete' and new decisions as list_action='new'
 * (delete always wins if the same IP appears in both this tick), then a
 * bounded slice of pending deletes/adds is applied to Cloudflare. This makes
 * a large warmup (which can take days at realistic decision volumes)
 * resumable — a rate limit or error mid-tick just leaves the rest pending
 * for next time — and an append-only add / id-targeted remove never
 * overwrites IPs some other process added to the same lists, unlike a
 * full-replace would.
 *
 * On the first sync after a cold start, the caller clears both the table and
 * the managed lists (clearAllIpLists) before this runs, so what's upserted
 * here is a clean full-state pull rather than layered on residue from a
 * previously interrupted warmup. Draining pending adds toward Cloudflare is
 * a separate, ongoing process that continues across ticks regardless of
 * isFirst — WARMED_UP only means "the initial full pull from LAPI has been
 * captured", not "every pending add has been pushed".
 *
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>} true unless this tick stopped early (rate
 *   limit or error) — an unplaced/still-pending remainder is normal,
 *   expected progress, not a failure.
 */
async function syncToIpLists(env, decisions) {
	logger.info('Starting IP list sync...');

	const backoffUntil = await getBackoffUntil(env.CROWDSECCFBOUNCERNS);
	if (backoffUntil && backoffUntil > new Date()) {
		logger.warn('Skipping IP list sync: backing off after a previous rate limit', {
			backoffUntil: backoffUntil.toISOString(),
		});
		return false;
	}

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const batchSize = env.IP_LIST_BATCH_SIZE ? parseInt(env.IP_LIST_BATCH_SIZE, 10) : DEFAULT_IP_LIST_BATCH_SIZE;
	const db = env.CROWDSECCFBOUNCER_QUEUE_DB;

	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	if (lists.length === 0) {
		logger.warn(`No IP Lists found with prefix "${prefix}"; skipping IP list sync`);
		// Nothing we can do without any managed lists; don't block warming on it.
		return true;
	}
	const listNameById = new Map(lists.map((l) => [l.id, l.name]));
	const listIds = lists.map((l) => l.id); // already name-sorted by listManagedIpLists

	// 1/2: split into upsert-ready entries, warning if the same IP shows up
	// in both batches this tick (delete always wins).
	const { newItems, deleteItems } = planUpserts(decisions.new, decisions.deleted, (msg, ctx) => logger.warn(msg, ctx));

	// 3: upsert new decisions (list_action='new' unless already 'listed'),
	// then expired decisions (list_action='delete', unconditionally).
	await upsertNews(db, newItems);
	await upsertDeletes(db, deleteItems);

	// 4: apply every pending delete now — removals aren't paced/batched like
	// adds are, since getting a ban off a list promptly matters more than
	// pacing removals.
	const { deletesByList, queueOnlyDeletes } = await readPendingDeletes(db);
	const confirmedIps = new Set(queueOnlyDeletes); // nothing to remove from Cloudflare; just drop the row

	// Per-list tallies for the completion summary below, so it's clear at a
	// glance which lists were actually touched this tick and by how much.
	const updatedLists = new Map(); // listName -> { added, removed }
	const bumpListStat = (listName, key, n) => {
		const stat = updatedLists.get(listName) || { added: 0, removed: 0 };
		stat[key] += n;
		updatedLists.set(listName, stat);
	};

	let removedCount = 0;
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
			await deleteQueueRows(db, [...confirmedIps]);
			return handleIpListError(env, e, `removing items from IP list ${listName}`);
		}
		for (const { ip } of toDelete) {
			confirmedIps.add(ip);
			removedCount++;
		}
		bumpListStat(listName, 'removed', toDelete.length);
	}
	// Rows Cloudflare confirmed removed, or that were never actually pushed,
	// are done for good — drop them from the table entirely.
	await deleteQueueRows(db, [...confirmedIps]);

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
	const db = env.CROWDSECCFBOUNCER_QUEUE_DB;
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
			// Both sync targets default to their historical behavior: KV sync
			// (the L7 bouncer worker's data source) is on unless explicitly
			// disabled; IP list sync (L3/4 firewall rules) is off unless opted in.
			const syncToKvEnabled = env.SYNC_TO_KV !== 'false';
			const syncToIpListsEnabled = env.SYNC_TO_IP_LISTS === 'true';

			if (!syncToKvEnabled && !syncToIpListsEnabled) {
				logger.error('Both SYNC_TO_KV and SYNC_TO_IP_LISTS are disabled; nothing to do');
				return;
			}

			// Validate required environment variables
			if (!env.LAPI_URL) {
				logger.error('LAPI_URL environment variable is not set');
				return;
			}

			if (!env.LAPI_KEY) {
				logger.error('LAPI_KEY secret is not set');
				return;
			}

			// CROWDSECCFBOUNCERNS is required in both modes: it's the L7 worker's
			// data store in KV mode, and it also holds the sync lock, warmed
			// flag, reset flag, and the IP list membership index in list mode.
			if (!env.CROWDSECCFBOUNCERNS) {
				logger.error('CROWDSECCFBOUNCERNS KV namespace is not bound');
				return;
			}

			if (!env.CF_ACCOUNT_ID) {
				logger.error('CF_ACCOUNT_ID environment variable is not set');
				return;
			}

			if (syncToKvEnabled && !env.CF_KV_NAMESPACE_ID) {
				logger.error('CF_KV_NAMESPACE_ID environment variable is not set (required when SYNC_TO_KV is enabled)');
				return;
			}

			if (syncToIpListsEnabled && !env.CROWDSECCFBOUNCER_QUEUE_DB) {
				logger.error('CROWDSECCFBOUNCER_QUEUE_DB D1 database is not bound (required when SYNC_TO_IP_LISTS is enabled)');
				return;
			}

			if (!env.CF_API_TOKEN) {
				logger.error('CF_API_TOKEN secret is not set (required for bulk KV/IP list operations)');
				return;
			}

			const lapiUrl = env.LAPI_URL.replace(/\/$/, ''); // Remove trailing slash if present

			// Acquire the sync lock so an overlapping cron tick (or a manual run
			// while a previous one is still in flight) doesn't fan out into a
			// full-sync storm against LAPI. Released in finally below; TTL is
			// only a backstop for a hard crash.
			const lockAcquired = await tryAcquireSyncLock(env.CROWDSECCFBOUNCERNS);
			if (!lockAcquired) {
				logger.info('Sync already in progress, skipping this run');
				return;
			}

			try {
				// Determine if this is the first fetch
				const isFirst = await isFirstFetch(env.CROWDSECCFBOUNCERNS);
				logger.info('Fetch type determined', { isFirstFetch: isFirst });

				// Check if reset is requested
				const resetRequested = await shouldReset(env.CROWDSECCFBOUNCERNS);

				// Clear residual state before the pull, both on an explicit RESET
				// and on the very first sync after a cold start — either way,
				// what's about to be fetched from LAPI (startup=true below) is the
				// full current state, not a diff, so stale entries from a previous
				// run (KV keys, D1 queue rows, IP list membership) must not survive
				// into it.
				if ((resetRequested || isFirst) && syncToKvEnabled) {
					logger.info('Clearing all decision keys from KV before fresh sync...');
					await resetAllDecisions(
						env.CF_ACCOUNT_ID,
						env.CF_KV_NAMESPACE_ID,
						env.CF_API_TOKEN,
						env.CROWDSECCFBOUNCERNS
					);
				}
				if ((resetRequested || isFirst) && syncToIpListsEnabled) {
					logger.info('Clearing all managed IP lists and the sync queue before fresh sync...');
					await clearAllIpLists(env);
				}
				if (resetRequested && !syncToKvEnabled) {
					// resetAllDecisions (above) already clears RESET as part of
					// wiping KV; in IP-list-only mode it's never called, so clear
					// the flag here or a manual RESET=true would never be
					// acknowledged and would keep re-triggering every tick.
					await clearResetFlag(env.CROWDSECCFBOUNCERNS);
				}

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

				// Log summary
				const duration = ((Date.now() - startTime) / 1000).toFixed(2);
				logger.info('Decision stream completed successfully', {
					duration: `${duration}s`,
					newDecisions: decisions.new.length,
					deletedDecisions: decisions.deleted.length,
				});

				// Handle HTTP 204 (LAPI has no decisions - delete all from KV)
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
					// Safe to mark warmed here: KV is now in its intended empty state,
					// so a crash at this point doesn't leave decisions unwritten.
					if (isFirst) {
						await markAsWarmed(env.CROWDSECCFBOUNCERNS);
						logger.info('Cache marked as warmed (LAPI has no decisions)');
					}
					const finalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
					logger.info('Cleared successfully (LAPI has no decisions)', {
						totalDuration: `${finalDuration}s`,
					});
					return; // Exit early - no further sync needed
				}

				if (syncToKvEnabled) {
					// Throws on failure, so reaching the next line means it fully completed.
					await syncToKv(env, decisions, isFirst);
				}

				// syncToIpLists upserts the full incoming batch into the D1 queue
				// before attempting any Cloudflare push, so WARMED_UP (meaning "the
				// initial full pull from LAPI has been captured") is correct even if
				// the push itself is rate-limited or fails — that failure only
				// delays draining the queue toward Cloudflare, a separate ongoing
				// process independent of isFirst. Only treat it as blocking warmup
				// if it fails outright (returns false).
				let ipListsSucceeded = true;
				if (syncToIpListsEnabled) {
					ipListsSucceeded = await syncToIpLists(env, decisions);
				}

				// Mark cache as warmed ONLY after all enabled sync targets have
				// captured this run's decisions. If this runs before every write
				// actually landed, a mid-sync crash leaves WARMED_UP=true with some
				// decisions never applied, and the next run does an incremental
				// fetch that never backfills what was missed — a silent
				// enforcement gap.
				if (isFirst && ipListsSucceeded) {
					await markAsWarmed(env.CROWDSECCFBOUNCERNS);
					logger.info('Cache marked as warmed (first sync complete)');
				} else if (isFirst) {
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
	},
};
