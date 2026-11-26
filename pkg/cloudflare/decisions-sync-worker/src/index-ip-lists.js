/**
 * CrowdSec Decisions Sync Worker — IP Lists target
 * Periodically fetches security decisions from CrowdSec LAPI and syncs
 * 'ip'/'range' scoped decisions into a single Cloudflare IP List (used for L3/4 firewall-rule bouncing).
 */

import logger from './utils/logger.js';
import { needWarmUp, markAsWarmed } from './core/decision-fetcher.js';
import { runScheduledSync } from './core/sync-runner.js';
import { filterIpListScopes } from './core/ip-list-processor.js';
import {
	listManagedIpLists,
	getListItems,
	addListItems,
	removeListItems,
	replaceListItems,
	getIpListBackoffUntil,
	setIpListBackoff,
	setIpListBackoffHours,
	clearIpListBackoff,
	MAX_ITEMS_PER_LIST,
	CloudflareApiError,
	requestCounts,
	resetRequestCounts,
} from './adapters/cloudflare-ip-lists.js';

const DEFAULT_IP_LIST_PREFIX = 'cs_';
const TEST_MODE_LIST_NAME = 'cs_00';
const TEST_MODE_IP_COUNT = 10;
// After every startup (full-replace) tick, wait this long before the next
// pull or any other IP-list action — win or lose, so a failing startup
// (list lookup or PUT) can't be retried in a tight loop either.
const IP_LIST_STARTUP_BACKOFF_HOURS = 25;

/**
 * Resolve the single IP list this worker manages (by IP_LIST_PREFIX),
 * warning if more than one list matches.
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {string} prefix
 * @returns {Promise<{id: string, name: string, numItems: number} | null>}
 */
async function resolveManagedList(env, prefix) {
	const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, prefix);
	if (lists.length === 0) {
		return null;
	}
	if (lists.length > 1) {
		logger.warn(
			`IP-list mode manages exactly one list but found ${lists.length} matching prefix "${prefix}"; using the first (name-sorted) and leaving the rest untouched`,
			{ lists: lists.map((l) => l.name) }
		);
	}
	return lists[0];
}

/**
 * Startup tick: 
 *  - Always a full LAPI pull
 *  - PUT whole list (capped) into the single managed list
 *  - On success, flag warmed up + Flag a 25h backoff timer to avoid rate limiting
 *    - The warmed up sync will take over
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>}
 */
async function syncToIpListStartup(env, decisions) {
	logger.info('Starting IP list sync (startup: full replace)...');
	resetRequestCounts();

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const maxItemsPerList = env.IP_LIST_MAX_ITEMS_PER_LIST ? parseInt(env.IP_LIST_MAX_ITEMS_PER_LIST, 10) : MAX_ITEMS_PER_LIST;

	try {
		// Dedupe: LAPI can emit multiple decisions for the same IP (different
		// scenarios/origins), which would otherwise inflate the list and the
		// truncation count for no reason.
		const allIps = [...new Set(filterIpListScopes(decisions.new).map((d) => d.value))];

		const list = await resolveManagedList(env, prefix);
		if (!list) {
			logger.error(`No IP List found with prefix "${prefix}"; pausing ${IP_LIST_STARTUP_BACKOFF_HOURS}h before retrying`);
			await setIpListBackoffHours(env.CROWDSECCFBOUNCERNS, IP_LIST_STARTUP_BACKOFF_HOURS);
			return false;
		}

		let ipsToPush = allIps;
		if (allIps.length > maxItemsPerList) {
			const truncatedCount = allIps.length - maxItemsPerList;
			logger.error(
				`Active decisions (${allIps.length}) exceed IP_LIST_MAX_ITEMS_PER_LIST (${maxItemsPerList}); truncating — ${truncatedCount} IP(s) will NOT be in list ${list.name} this tick`,
				{ list: list.name, totalDecisions: allIps.length, maxItemsPerList, truncatedCount }
			);
			ipsToPush = allIps.slice(0, maxItemsPerList);
		}

		logger.info(`Replacing IP list ${list.name} entirely...`, {
			list: list.name,
			size: ipsToPush.length,
			max: maxItemsPerList,
		});
		await replaceListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, ipsToPush);

		await markAsWarmed(env.CROWDSECCFBOUNCERNS);
		logger.info('IP list startup sync completed successfully', { list: list.name, size: ipsToPush.length });
		return true;
	} catch (e) {
		return handleIpListError(env, e, 'replacing the IP list on startup');
	} finally {
		// Win or lose, pace the next IP-list action 25h out — a failed
		// startup leaves WARMED_UP false, so it just retries as a startup
		// again once the pause clears.
		await setIpListBackoffHours(env.CROWDSECCFBOUNCERNS, IP_LIST_STARTUP_BACKOFF_HOURS);
		logger.info('IP list startup sync request tally', {
			cloudflareApiRequests: requestCounts.cloudflareApi,
			cloudflareApiByEndpoint: { ...requestCounts.cloudflareApiByEndpoint },
		});
	}
}

/**
 * Warmed (incremental) tick: decisions.new/decisions.deleted are a delta.
 * Adds go via plain POST, removes via plain DELETE (never a full-replace
 * PUT) — item ids for removes are resolved by reading the list's current
 * contents first, only when there's actually something to delete.
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>}
 */
async function syncToIpListWarmed(env, decisions) {
	logger.info('Starting IP list sync (warmed: add/remove)...');
	resetRequestCounts();

	const prefix = env.IP_LIST_PREFIX || DEFAULT_IP_LIST_PREFIX;
	const maxItemsPerList = env.IP_LIST_MAX_ITEMS_PER_LIST ? parseInt(env.IP_LIST_MAX_ITEMS_PER_LIST, 10) : MAX_ITEMS_PER_LIST;

	const newIps = [...new Set(filterIpListScopes(decisions.new).map((d) => d.value))];
	const deletedIps = [...new Set(filterIpListScopes(decisions.deleted).map((d) => d.value))];

	if (newIps.length === 0 && deletedIps.length === 0) {
		logger.info('No ip/range-scoped decisions this tick; nothing to do');
		return true;
	}

	try {
		const list = await resolveManagedList(env, prefix);
		if (!list) {
			logger.warn(`No IP List found with prefix "${prefix}"; skipping this tick (${newIps.length} add(s), ${deletedIps.length} removal(s) not applied)`);
			return true;
		}

		let itemIdByIp = new Map();
		if (deletedIps.length > 0) {
			try {
				itemIdByIp = await getListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id);
			} catch (e) {
				return handleIpListError(env, e, `reading current items of list ${list.name} before removals`);
			}
		}
		const itemIdsToRemove = deletedIps.map((ip) => itemIdByIp.get(ip)).filter((id) => id !== undefined);
		const notListed = deletedIps.length - itemIdsToRemove.length;
		if (notListed > 0) {
			logger.warn(`${notListed} IP(s) reported as expired were not found in list ${list.name}; nothing to remove for them`, { list: list.name });
		}

		// Clamp adds against the list's own live size (net of this tick's
		// removals) so a tick can never push the real list over
		// maxItemsPerList. Anything clamped off is simply not added this
		// tick — there's no local queue to retry it from later, so it's
		// lost until the next startup pull picks it back up.
		const sizeAfterDeletes = Math.max(0, list.numItems - itemIdsToRemove.length);
		const available = Math.max(0, maxItemsPerList - sizeAfterDeletes);
		let ipsToAdd = newIps;
		if (ipsToAdd.length > available) {
			const droppedCount = ipsToAdd.length - available;
			logger.error(
				`List ${list.name} has no room for ${droppedCount} of ${ipsToAdd.length} new IP(s) (maxItemsPerList=${maxItemsPerList}); they will NOT be added this tick and won't be retried until the next startup pull`,
				{ list: list.name, planned: ipsToAdd.length, available, dropped: droppedCount }
			);
			ipsToAdd = ipsToAdd.slice(0, available);
		}

		// Alternate delete/add order by day parity — a diagnostic for
		// suspected Cloudflare rate-limit starvation: if one op eats the
		// tick's rate-limit budget (or the account's single pending-bulk-
		// operation slot) before the other runs, the other never happens on
		// a day where it always goes second. Alternating lets us see
		// whether the order correlates with that pattern.
		const performAddFirst = new Date().getUTCDate() % 2 === 0;
		logger.info(`Updating IP list ${list.name} via add/remove...`, {
			list: list.name,
			added: ipsToAdd.length,
			removed: itemIdsToRemove.length,
			order: performAddFirst ? 'add-then-delete' : 'delete-then-add',
		});

		let addedCount = 0;
		let removedCount = 0;
		try {
			const doAdd = async () => {
				await addListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, ipsToAdd);
				addedCount = ipsToAdd.length;
			};
			const doRemove = async () => {
				await removeListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, itemIdsToRemove);
				removedCount = itemIdsToRemove.length;
			};
			if (performAddFirst) {
				await doAdd();
				await doRemove();
			} else {
				await doRemove();
				await doAdd();
			}
		} catch (e) {
			const remainingAdds = ipsToAdd.length - addedCount;
			const remainingRemoves = itemIdsToRemove.length - removedCount;
			logger.error(`Failed partway through updating list ${list.name}; ${remainingAdds} add(s) and ${remainingRemoves} removal(s) did not complete this tick`, {
				list: list.name,
				added: addedCount,
				removed: removedCount,
				remainingAdds,
				remainingRemoves,
			});
			return handleIpListError(env, e, `updating IP list ${list.name} (add/remove)`);
		}

		await clearIpListBackoff(env.CROWDSECCFBOUNCERNS);
		logger.info(`IP list ${list.name} updated successfully`, { list: list.name, added: addedCount, removed: removedCount });
		return true;
	} finally {
		logger.info('IP list warmed sync request tally', {
			cloudflareApiRequests: requestCounts.cloudflareApi,
			cloudflareApiByEndpoint: { ...requestCounts.cloudflareApiByEndpoint },
		});
	}
}

/**
 * Test mode: pulls the full decision set (startup=true, done by the caller)
 * and PUTs only the first TEST_MODE_IP_COUNT ip/range-scoped IPs into the
 * fixed TEST_MODE_LIST_NAME list, bypassing the normal startup/warmed sync.
 * For poking a known-small, known list to sanity check credentials/API
 * access without touching real traffic-facing lists.
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {import('./types.js').DecisionStreamResponse} decisions
 * @returns {Promise<boolean>}
 */
async function runTestModeSync(env, decisions) {
	logger.info(`Starting test mode sync: PUTting up to ${TEST_MODE_IP_COUNT} IP(s) into ${TEST_MODE_LIST_NAME}...`);
	resetRequestCounts();

	try {
		const ips = [...new Set(filterIpListScopes(decisions.new).map((d) => d.value))].slice(0, TEST_MODE_IP_COUNT);

		const lists = await listManagedIpLists(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, TEST_MODE_LIST_NAME);
		const list = lists.find((l) => l.name === TEST_MODE_LIST_NAME);
		if (!list) {
			logger.error(`Test mode list "${TEST_MODE_LIST_NAME}" not found; create it manually first`);
			return false;
		}

		await replaceListItems(env.CF_ACCOUNT_ID, env.CF_API_TOKEN, list.id, ips);
		logger.info(`Test mode: successfully put ${ips.length} IP(s) into ${TEST_MODE_LIST_NAME}`, {
			list: TEST_MODE_LIST_NAME,
			count: ips.length,
			ips,
		});
		return true;
	} catch (e) {
		return handleIpListError(env, e, `test mode PUT into ${TEST_MODE_LIST_NAME}`);
	} finally {
		logger.info('Test mode sync request tally', {
			cloudflareApiRequests: requestCounts.cloudflareApi,
			cloudflareApiByEndpoint: { ...requestCounts.cloudflareApiByEndpoint },
		});
	}
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
		await setIpListBackoff(env.CROWDSECCFBOUNCERNS, e.retryAfterSeconds);
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
 * @param {ScheduledEvent} event
 * @param {import('./types.js').CrowdSecEnv} env
 * @param {ExecutionContext} _ctx
 */
async function scheduled(event, env, _ctx) {
	// TEST_MODE only PUT 10 IPs to test rate limiting
	const testModeEnabled = env.TEST_MODE === 'true';

	await runScheduledSync(event, env, {
		shouldSkip: async (env) => {
			const ipListBackoffUntil = await getIpListBackoffUntil(env.CROWDSECCFBOUNCERNS);
			if (ipListBackoffUntil && ipListBackoffUntil > new Date()) {
				logger.warn('Waiting out a previous rate limit or post-startup pause; doing nothing this tick', {
					backoffUntil: ipListBackoffUntil.toISOString(),
				});
				return true;
			}
			return false;
		},
		needStartUpFetch: async (env) => {
			if (testModeEnabled) return true;
			return needWarmUp(env.CROWDSECCFBOUNCERNS);
		},
		onResetRequested: async () => {
			// IP-list mode has nothing to proactively clear on RESET: it just
			// forces the next tick to be a startup pull, whose PUT already
			// replaces the list's entire contents outright.
			logger.info('RESET requested: next IP list tick will be a full startup pull (PUT replaces the list outright)');
		},
		runSync: async (env, decisions, needStartUpFetch) => {
			if (testModeEnabled) {
				return runTestModeSync(env, decisions);
			}
			return needStartUpFetch ? syncToIpListStartup(env, decisions) : syncToIpListWarmed(env, decisions);
		},
	});
}

export default { scheduled };
