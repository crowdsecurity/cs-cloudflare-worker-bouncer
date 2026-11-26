#!/usr/bin/env node
/**
 * Local benchmark for the IP-list re-sync diff (core/ip-list-reconciler.js).
 *
 * Two modes:
 *
 *   1. Live: pulls a real LAPI startup snapshot and a real Cloudflare IP
 *      list's current membership, measuring each step (LAPI pull, list
 *      pagination, diff computation). Whatever it downloads is saved to
 *      --pull/--list (default pull.csv/list.csv) so a later run can replay
 *      the exact same data offline.
 *
 *        LAPI_URL=... LAPI_KEY=... CF_ACCOUNT_ID=... CF_API_TOKEN=... \
 *        node scripts/bench-resync.mjs --list-id <cloudflare_list_id>
 *
 *   2. Offline: no network at all, just replays two previously-saved CSVs
 *      and times the diff:
 *
 *        node scripts/bench-resync.mjs --pull pull.csv --list list.csv
 *
 * CSV formats (no header):
 *   pull.csv: one IP/range per line (the desired set from a startup pull)
 *   list.csv: "ip,item_id" per line (the list's current membership)
 */

import { readFile, writeFile } from 'node:fs/promises';
import { diffIpList } from '../src/core/ip-list-reconciler.js';

function parseArgs(argv) {
	const args = { pull: 'pull.csv', list: 'list.csv', listId: null };
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === '--pull') args.pull = argv[++i];
		else if (a === '--list') args.list = argv[++i];
		else if (a === '--list-id') args.listId = argv[++i];
		else if (a === '--help' || a === '-h') args.help = true;
	}
	return args;
}

function printHelp() {
	console.log(`Usage:
  Live run (hits real LAPI + Cloudflare API, saves what it downloads):
    LAPI_URL=... LAPI_KEY=... CF_ACCOUNT_ID=... CF_API_TOKEN=... \\
      node scripts/bench-resync.mjs --list-id <cloudflare_list_id> [--pull pull.csv] [--list list.csv]

  Offline run (replays saved CSVs, diff only, no network):
    node scripts/bench-resync.mjs --pull pull.csv --list list.csv
`);
}

async function csvFileExists(path) {
	try {
		await readFile(path);
		return true;
	} catch {
		return false;
	}
}

function parsePullCsv(text) {
	return text
		.split('\n')
		.map((l) => l.trim())
		.filter((l) => l.length > 0);
}

function parseListCsv(text) {
	const items = new Map();
	for (const line of text.split('\n')) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		const [ip, id] = trimmed.split(',');
		items.set(ip, id);
	}
	return items;
}

function writePullCsv(ips) {
	return ips.join('\n') + '\n';
}

function writeListCsv(items) {
	let out = '';
	for (const [ip, id] of items) {
		out += `${ip},${id}\n`;
	}
	return out;
}

async function fetchStartupDecisionIps(lapiUrl, lapiKey) {
	const url = `${lapiUrl.replace(/\/$/, '')}/v1/decisions/stream?startup=true&scopes=ip,range`;
	const response = await fetch(url, {
		method: 'GET',
		headers: { 'X-Api-Key': lapiKey, 'User-Agent': 'cloudflare-worker-bouncer/bench' },
	});
	if (!response.ok) {
		throw new Error(`LAPI request failed: ${response.status} ${await response.text()}`);
	}
	const data = await response.json();
	const decisions = data.new || [];
	return [...new Set(decisions.filter((d) => d && d.value).map((d) => d.value))];
}

async function fetchAllListItemsLive(accountId, apiToken, listId) {
	const items = new Map();
	let cursor = null;
	do {
		const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${accountId}/rules/lists/${listId}/items`);
		url.searchParams.set('per_page', '1000');
		if (cursor) url.searchParams.set('cursor', cursor);

		const response = await fetch(url, {
			method: 'GET',
			headers: { Authorization: `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
		});
		if (!response.ok) {
			throw new Error(`Cloudflare list-items request failed: ${response.status} ${await response.text()}`);
		}
		const data = await response.json();
		for (const item of data.result || []) {
			items.set(item.ip, item.id);
		}
		cursor = data.result_info?.cursor || null;
	} while (cursor);
	return items;
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	if (args.help) {
		printHelp();
		return;
	}

	const haveCsvsOnDisk = (await csvFileExists(args.pull)) && (await csvFileExists(args.list));
	const haveLiveCreds = process.env.LAPI_URL && process.env.LAPI_KEY && process.env.CF_ACCOUNT_ID && process.env.CF_API_TOKEN;

	let desiredIps;
	let currentItems;

	if (haveLiveCreds) {
		if (!args.listId) {
			console.error('--list-id <cloudflare_list_id> is required when running live (credentials are set)');
			process.exitCode = 1;
			return;
		}

		console.log('Live mode: pulling from LAPI and Cloudflare...');

		let t0 = performance.now();
		desiredIps = await fetchStartupDecisionIps(process.env.LAPI_URL, process.env.LAPI_KEY);
		const lapiMs = performance.now() - t0;
		console.log(`LAPI startup pull: ${desiredIps.length} ip/range decision(s) in ${lapiMs.toFixed(1)}ms`);

		t0 = performance.now();
		currentItems = await fetchAllListItemsLive(process.env.CF_ACCOUNT_ID, process.env.CF_API_TOKEN, args.listId);
		const listMs = performance.now() - t0;
		console.log(`Cloudflare list pull: ${currentItems.size} item(s) in ${listMs.toFixed(1)}ms`);

		await writeFile(args.pull, writePullCsv(desiredIps));
		await writeFile(args.list, writeListCsv(currentItems));
		console.log(`Saved downloaded data to ${args.pull} and ${args.list} for offline replay`);
	} else if (haveCsvsOnDisk) {
		console.log(`Offline mode: replaying ${args.pull} and ${args.list} (no network)`);
		desiredIps = parsePullCsv(await readFile(args.pull, 'utf8'));
		currentItems = parseListCsv(await readFile(args.list, 'utf8'));
		console.log(`Loaded ${desiredIps.length} desired ip/range(s), ${currentItems.size} current list item(s)`);
	} else {
		console.error('Neither live credentials (LAPI_URL/LAPI_KEY/CF_ACCOUNT_ID/CF_API_TOKEN) nor both CSV files were found.\n');
		printHelp();
		process.exitCode = 1;
		return;
	}

	const t0 = performance.now();
	const { toAdd, toRemove } = diffIpList(desiredIps, currentItems);
	const diffMs = performance.now() - t0;

	console.log('\n--- diff result ---');
	console.log(`toAdd:    ${toAdd.length}`);
	console.log(`toRemove: ${toRemove.length}`);
	console.log(`diff computed in ${diffMs.toFixed(3)}ms (desired=${desiredIps.length}, current=${currentItems.size})`);
}

main().catch((err) => {
	console.error(err);
	process.exitCode = 1;
});
