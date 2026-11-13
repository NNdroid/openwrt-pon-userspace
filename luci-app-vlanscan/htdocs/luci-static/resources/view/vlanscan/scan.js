// SPDX-License-Identifier: Apache-2.0

'use strict';
'require fs';
'require poll';
'require dom';
'require ui';
'require view';

var CTL = '/usr/libexec/vlanscan-ctl';

/* Keep the log tab responsive even if a scanner ever becomes chatty. */
var MAX_LOG_LINES = 1500;

/* Must stay in sync with COMMON_VLANS in the scanner. Used only to estimate
 * an explicit "common" probe - never as an implicit default. */
var COMMON_VLAN_IDS = [10, 35, 41, 45, 48, 85, 100, 101, 102, 110, 130, 200,
	451, 1000, 1001, 2000, 3000, 3961, 4001];
var ALL_VLAN_COUNT = 4094;
var PROBE_INTERVAL_MS = 200;
var FRAMES_PER_VLAN = 3;

/* Count the VLANs a candidate expression expands to, or null when the
 * expression is not valid yet. Mirrors vlanscan's parse_vlan_list(). */
function countVlans(text) {
	var value = (text || '').trim();
	if (!value)
		return 0;
	var ids = [];
	var parts = value.split(',');
	for (var i = 0; i < parts.length; i++) {
		var part = parts[i].trim();
		if (/^all$/i.test(part))
			return ALL_VLAN_COUNT;
		if (/^common$/i.test(part)) {
			ids = ids.concat(COMMON_VLAN_IDS);
			continue;
		}
		var range = /^(\d+)-(\d+)$/.exec(part);
		if (range) {
			var from = parseInt(range[1], 10), to = parseInt(range[2], 10);
			if (from < 1 || to > ALL_VLAN_COUNT || from > to)
				return null;
			for (var vlan = from; vlan <= to; vlan++)
				ids.push(vlan);
			continue;
		}
		if (!/^\d+$/.test(part))
			return null;
		var id = parseInt(part, 10);
		if (id < 1 || id > ALL_VLAN_COUNT)
			return null;
		ids.push(id);
	}
	var seen = {}, unique = 0;
	for (var j = 0; j < ids.length; j++) {
		if (!seen[ids[j]]) {
			seen[ids[j]] = 1;
			unique++;
		}
	}
	return unique;
}

function durationText(seconds) {
	if (seconds < 60)
		return Math.round(seconds) + ' s';
	if (seconds < 3600)
		return Math.round(seconds / 60) + ' min';
	return (seconds / 3600).toFixed(1) + ' h';
}

/* Job logs are files, not terminals. Older scanner builds ended progress
 * heartbeats with a bare CR to overwrite the line in place; a browser <pre>
 * does not treat CR as a line break, so normalize CR / CRLF to LF here. */
function normalizeLog(text) {
	return (text || '').replace(/\r\n?/g, '\n');
}

/* Theme-neutral styles: every surface uses translucent neutral tones and
 * inherits the current text colour, so the view stays readable in both
 * light and dark LuCI themes. Accent colours are used only as small chips. */
var CSS = [
	'.vscan-card{background:rgba(127,127,127,.055);border:1px solid rgba(127,127,127,.2);border-radius:12px;padding:16px 18px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.05);}',
	'.vscan-card.status-running{border-top:3px solid #22a06b;}',
	'.vscan-card.status-completed{border-top:3px solid #2d8cf0;}',
	'.vscan-card.status-failed{border-top:3px solid #d0453b;}',
	'.vscan-card.status-interrupted{border-top:3px solid #b5650a;}',
	'.vscan-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}',
	'.vscan-badges{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;}',
	'.vscan-status{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:11px;font-size:11.5px;font-weight:600;background:rgba(127,127,127,.14);color:inherit;}',
	'.vscan-status-dot{width:7px;height:7px;border-radius:50%;flex:none;}',
	'.vscan-title{font-weight:600;font-size:15px;color:inherit;}',
	'.vscan-sub{opacity:.68;font-size:12px;margin-left:2px;}',
	'.vscan-actions{display:inline-flex;gap:6px;}',
	'.vscan-tag{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11.5px;background:rgba(127,127,127,.14);color:inherit;}',
	'.vscan-tag.accent{background:rgba(45,140,240,.14);border-left:3px solid #2d8cf0;}',
	'.vscan-params{display:flex;flex-wrap:wrap;gap:6px;margin:11px 0 2px;}',
	'.vscan-param{display:inline-flex;align-items:baseline;gap:6px;padding:3px 9px;border:1px solid rgba(127,127,127,.2);border-radius:8px;font-size:12px;max-width:100%;}',
	'.vscan-param-key{opacity:.62;white-space:nowrap;}',
	'.vscan-param-val{font-weight:600;word-break:break-all;}',
	'.vscan-param-val.mono{font-family:monospace;font-weight:500;}',
	'.vscan-progress-wrap{margin:10px 0 2px;}',
	'.vscan-progress-meta{font-size:12px;opacity:.75;margin-bottom:5px;}',
	'.vscan-progress{height:6px;border-radius:6px;background:rgba(127,127,127,.18);overflow:hidden;}',
	'.vscan-progress > div{height:100%;border-radius:6px;background:#2d8cf0;transition:width .3s ease;}',
	'.vscan-results-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;font-weight:600;font-size:13px;color:inherit;margin:14px 0 4px;}',
	'.vscan-count{font-weight:500;font-size:11.5px;padding:2px 9px;border-radius:10px;background:rgba(45,140,240,.13);}',
	'.vscan-table{width:100%;border-collapse:collapse;margin-top:4px;font-size:13px;}',
	'.vscan-table th{text-align:left;background:rgba(127,127,127,.1);padding:8px 10px;border-bottom:2px solid rgba(127,127,127,.2);color:inherit;font-weight:600;white-space:nowrap;}',
	'.vscan-table td{padding:7px 10px;border-bottom:1px solid rgba(127,127,127,.13);vertical-align:middle;}',
	'.vscan-table tr:last-child td{border-bottom:none;}',
	'.vscan-untagged td:first-child{font-weight:600;color:#c47b10;}',
	'.vscan-total td{font-weight:600;background:rgba(127,127,127,.07);border-top:2px solid rgba(127,127,127,.2);}',
	'.vscan-vid{font-weight:600;font-size:13.5px;}',
	'.vscan-mono{font-family:monospace;font-size:12.5px;}',
	'.vscan-chip{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;margin:1px 4px 1px 0;white-space:nowrap;background:rgba(127,127,127,.13);color:inherit;border-left:3px solid rgba(127,127,127,.5);}',
	'.vscan-chip.pppoe{border-left-color:#2d8cf0;}',
	'.vscan-chip.dhcp{border-left-color:#22a06b;}',
	'.vscan-chip.l3{border-left-color:#b5650a;}',
	'.vscan-chip.arp{border-left-color:#888;}',
	'.vscan-chip.ipv4{border-left-color:#0b8fa8;}',
	'.vscan-chip.ipv6{border-left-color:#7a52c7;}',
	'.vscan-chip.igmp{border-left-color:#c47b10;}',
	'.vscan-chip.small{padding:0 6px;font-size:10.5px;margin-left:6px;}',
	'.vscan-empty{opacity:.55;font-style:italic;padding:6px 0;}',
	'.vscan-note{color:#d0453b;font-size:12.5px;margin-top:8px;}',
	'.vscan-tabs{display:flex;gap:2px;border-bottom:1px solid rgba(127,127,127,.25);margin:16px 0 16px;flex-wrap:wrap;}',
	'.vscan-tab{appearance:none;-webkit-appearance:none;background:transparent;border:0;border-bottom:2px solid transparent;padding:9px 17px;font-family:inherit;font-size:13.5px;font-weight:600;color:inherit;opacity:.62;cursor:pointer;}',
	'.vscan-tab:hover{opacity:.9;}',
	'.vscan-tab.active{opacity:1;border-bottom-color:#2d8cf0;color:#2d8cf0;}',
	'.vscan-tab-count{display:inline-block;margin-left:7px;padding:0 6px;border-radius:9px;font-size:10.5px;font-weight:600;background:rgba(127,127,127,.18);color:inherit;}',
	'.vscan-tab.active .vscan-tab-count{background:rgba(45,140,240,.16);color:inherit;}',
	'.vscan-panel{display:none;}',
	'.vscan-panel.active{display:block;}',
	'.vscan-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px;}',
	'.vscan-toolbar label{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;opacity:.85;cursor:pointer;}',
	'.vscan-toolbar select{max-width:340px;}',
	'.vscan-log-summary{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;}',
	'.vscan-log-pre{max-height:520px;min-height:180px;overflow:auto;background:rgba(127,127,127,.09);border:1px solid rgba(127,127,127,.18);border-radius:8px;padding:11px 13px;margin:10px 0 0;white-space:pre-wrap;word-break:break-word;font-family:monospace;font-size:12px;line-height:1.55;color:inherit;}',
	'.vscan-log-pre.empty{opacity:.62;font-style:italic;font-family:inherit;}',
	'.vscan-log-meta{font-size:11.5px;opacity:.65;margin-top:9px;}',
	'.vscan-section-title{font-weight:600;font-size:12px;opacity:.7;letter-spacing:.04em;text-transform:uppercase;margin:6px 0 2px;}',
	'.vscan-hint{opacity:.68;font-size:12px;line-height:1.5;}'
].join('\n');

var cssInjected = false;
function ensureCss() {
	if (cssInjected)
		return;
	cssInjected = true;
	try {
		document.head.appendChild(E('style', {}, CSS));
	} catch (e) { /* non-fatal */ }
}

/* Robust file read: LuCI's fs.read() may return either a plain string or an
 * object shaped like { data: <string> } depending on the version. Normalize
 * both to a text string so JSON parsing always works. */
function readText(path) {
	return Promise.resolve()
		.then(function () { return fs.read(path); })
		.then(function (res) {
			if (typeof res === 'string')
				return res;
			if (res && typeof res.data === 'string')
				return res.data;
			if (res && res.data && typeof res.data === 'object')
				return JSON.stringify(res.data);
			return '';
		})
		.catch(function () { return ''; });
}

function ctlExec(args) {
	return fs.exec(CTL, args).catch(function (error) {
		ui.addNotification(null, E('p', {}, _('VLAN scan control failed: %s').format(error.message || error)), 'error');
		return null;
	});
}

/* Status colours are theme-neutral and reused by the badge and the card accent. */
var STATUS_COLORS = {
	running: '#22a06b',
	completed: '#2d8cf0',
	failed: '#d0453b',
	interrupted: '#b5650a'
};

/* Localised status text. The job.state comes from the backend as a bare
 * English word; surface it in the UI language instead of the raw string. */
function statusText(status) {
	switch (status) {
		case 'running': return _('Running');
		case 'completed': return _('Completed');
		case 'failed': return _('Failed');
		case 'interrupted': return _('Interrupted');
		default: return status || '?';
	}
}

function statusBadge(status) {
	var color = STATUS_COLORS[status] || 'rgba(127,127,127,.55)';
	return E('span', { 'class': 'vscan-status' }, [
		E('span', { 'class': 'vscan-status-dot', 'style': 'background:' + color }, ''),
		statusText(status)
	]);
}

function jobTime(id) {
	var seconds = parseInt(id, 10);
	if (isNaN(seconds))
		return id;
	return new Date(seconds * 1000).toLocaleString();
}

function modeText(mode) {
	if (mode === 'probe')
		return _('Probe (discovery frames on candidate VLANs)');
	if (mode === 'passive')
		return _('Passive listen (no packets sent)');
	return mode || '?';
}

// Version-independent confirmation dialog. Some LuCI snapshots do not ship
// ui.confirm(), so fall back to a showModal-built dialog, then to the native
// confirm as a last resort. Returns a Promise<boolean>.
function askConfirm(title, message, confirmLabel) {
	if (typeof ui.confirm === 'function')
		return ui.confirm(title, message);
	if (typeof ui.showModal === 'function') {
		return new Promise(function (resolve) {
			var ok = E('button', { 'class': 'btn cbi-button cbi-button-negative' }, confirmLabel || _('OK'));
			var cancel = E('button', { 'class': 'btn cbi-button' }, _('Cancel'));
			ok.addEventListener('click', function () {
				if (ui.hideModal) ui.hideModal();
				resolve(true);
			});
			cancel.addEventListener('click', function () {
				if (ui.hideModal) ui.hideModal();
				resolve(false);
			});
			ui.showModal(title, E('div', {}, [
				E('p', {}, message),
				E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [ cancel, ok ])
			]));
		});
	}
	return Promise.resolve(window.confirm(message));
}

function chipClass(name) {
	if (name.indexOf('pppoe') === 0)
		return 'pppoe';
	if (name.indexOf('arp') === 0)
		return 'arp';
	if (name.indexOf('dhcp') === 0)
		return 'dhcp';
	if (name === 'ipv4')
		return 'ipv4';
	if (name === 'ipv6' || name === 'ndp')
		return 'ipv6';
	if (name.indexOf('igmp') === 0)
		return 'igmp';
	return 'other';
}

function classChips(classes) {
	var keys = Object.keys(classes || {}).sort();
	if (!keys.length)
		return E('span', { 'class': 'vscan-empty' }, '–');
	return E('span', {}, keys.map(function (name) {
		return E('span', { 'class': 'vscan-chip ' + chipClass(name) },
			name + ' ' + classes[name]);
	}));
}

/* Small service badges shown next to a probed VLAN id. */
function serviceChips(entry) {
	var services = [];
	if (entry.pppoe)
		services.push([ 'pppoe', 'PPPoE' ]);
	if (entry.dhcp_offer)
		services.push([ 'dhcp', 'DHCP' ]);
	if (entry.gateway)
		services.push([ 'l3', 'L3' ]);
	if (!services.length)
		return null;
	return E('span', {}, services.map(function (service) {
		return E('span', { 'class': 'vscan-chip small ' + service[0] }, service[1]);
	}));
}

function progressText(job) {
	var progress = job.progress || {};
	if (job.mode == 'probe') {
		if (progress.total)
			return _('VLAN %d (%d of %d)').format(progress.vlan || 0, progress.index || 0, progress.total);
		return _('starting…');
	}
	if (progress.total_seconds)
		return _('%ds / %ds').format(progress.seconds || 0, progress.total_seconds);
	return _('listening…');
}

function progressPercent(job) {
	var progress = job.progress || {};
	if (job.mode == 'probe' && progress.total)
		return Math.min(100, Math.round(100 * (progress.index || 0) / progress.total));
	if (progress.total_seconds)
		return Math.min(100, Math.round(100 * (progress.seconds || 0) / progress.total_seconds));
	return 0;
}

/* Parameter chips: show every value that actually went into the scan.
 * The backend now publishes the real candidate list, so this no longer
 * misleadingly says "all" when only the default short list was probed. */
function paramChips(job) {
	var params = job.params || {};
	var items = [
		[ _('Mode'), modeText(job.mode), false ],
		[ _('Interface'), job.interface || _('auto-detect'), true ]
	];
	if (job.mode == 'probe') {
		/* The scanner writes job.json a moment after ctl reports "running";
		 * until then the candidate list is unknown, not empty. */
		var vlanText = '…';
		if (Array.isArray(params.vlans)) {
			var vlans = params.vlans;
			vlanText = !vlans.length ? _('none (no candidates)')
				: (vlans.length > 12
					? vlans.slice(0, 12).join(', ') + ' … (+' + (vlans.length - 12) + ')'
					: vlans.join(', '));
		}
		items.push([ _('VLANs'), vlanText, false ]);
		items.push([ _('Source MAC'), params.mac || _('auto (PON MAC)'), true ]);
		if (params.probe_wait)
			items.push([ _('Reply wait'), params.probe_wait + ' ms', false ]);
		if (params.arp_target)
			items.push([ _('ARP target'), params.arp_target, true ]);
		if (params.vendor_class)
			items.push([ _('Vendor class'), params.vendor_class, true ]);
	}
	else {
		items.push([ _('Duration'), (params.duration || '?') + ' s', false ]);
	}
	return E('div', { 'class': 'vscan-params' }, items.map(function (item) {
		return E('span', { 'class': 'vscan-param' }, [
			E('span', { 'class': 'vscan-param-key' }, item[0] + ':'),
			E('span', { 'class': 'vscan-param-val' + (item[2] ? ' mono' : '') }, String(item[1]))
		]);
	}));
}

return view.extend({
	load: function () {
		return Promise.all([
			ctlExec([ 'interfaces' ]),
			ctlExec([ 'list' ])
		]);
	},

	fetchJobs: function () {
		var self = this;
		return ctlExec([ 'list' ]).then(function (reply) {
			if (!reply || reply.code != 0)
				return [];
			var entries;
			try {
				entries = JSON.parse(reply.stdout || '[]');
			}
			catch (error) {
				return [];
			}
			if (!Array.isArray(entries))
				return [];

			/* Finished jobs never change again, but the scanner prints a few
			 * summary lines AFTER publishing the final status. Keep reading
			 * for two polls after the transition, then serve from cache.
			 * This cuts the 3*N rpcd reads per 3s poll down to the three
			 * needed by the (usually single) running job. */
			var cache = self.jobCache || (self.jobCache = {});
			var seen = {};
			return Promise.all(entries.map(function (entry) {
				var base = '/tmp/vlanscan/' + entry.id;
				seen[entry.id] = true;
				var cached = cache[entry.id];
				if (entry.status != 'running' && cached &&
					cached.status == entry.status && cached.settled)
					return Promise.resolve(cached.job);

				return Promise.all([
					readText(base + '/job.json'),
					readText(base + '/results.json'),
					readText(base + '/log')
				]).then(function (texts) {
					var job = {};
					try {
						job = JSON.parse(texts[0] || '{}');
					}
					catch (error) { /* job.json not written yet */ }
					job.id = entry.id;
					job.status = entry.status;
					if (texts[1]) {
						try {
							var parsed = JSON.parse(texts[1]);
							if (Array.isArray(parsed))
								job.results = parsed;
						}
						catch (error) { /* partial write, retry next poll */ }
					}
					job.log = texts[2] || '';
					if (entry.status != 'running')
						cache[entry.id] = {
							status: entry.status,
							settled: !!(cached && cached.status == entry.status),
							job: job
						};
					else
						delete cache[entry.id];
					return job;
				});
			})).then(function (jobs) {
				Object.keys(cache).forEach(function (id) {
					if (!seen[id])
						delete cache[id];
				});
				return jobs;
			});
		});
	},

	renderResults: function (job) {
		var self = this;
		var results = job.results;
		var isProbe = (job.mode == 'probe');
		if (!results || !results.length)
			return E('div', { 'class': 'vscan-empty' }, isProbe
				? _('No live VLANs found among the probed candidates. Try a longer reply wait, a different source MAC or vendor class, or probing all VLANs.')
				: _('No packets captured during this scan window.'));

		// Build one flat array of <tr> nodes. Older LuCI E() does not
		// recursively flatten nested arrays, which would stringify them as
		// "[object HTMLTableRowElement],..." instead of appending rows.
		var rows = [];
		rows.push(E('tr', {}, isProbe ? [
			E('th', {}, _('VLAN')),
			E('th', {}, _('PPPoE')),
			E('th', {}, _('Gateway (ARP)')),
			E('th', {}, _('DHCP offer')),
			E('th', {}, _('DHCP server'))
		] : [
			E('th', {}, _('VLAN')),
			E('th', {}, _('Packets')),
			E('th', {}, _('Traffic classes'))
		]));

		var total = 0;
		results.forEach(function (entry) {
			if (isProbe) {
				var vidCell = [ E('span', { 'class': 'vscan-vid' }, String(entry.vid)) ];
				var chips = serviceChips(entry);
				if (chips)
					vidCell.push(chips);
				rows.push(E('tr', {}, [
					E('td', {}, vidCell),
					E('td', {}, entry.pppoe
						? E('span', { 'class': 'vscan-chip pppoe' }, _('yes (PADO)'))
						: E('span', { 'class': 'vscan-empty' }, '–')),
					E('td', { 'class': 'vscan-mono' }, entry.gateway || '–'),
					E('td', { 'class': 'vscan-mono' }, entry.dhcp_offer || '–'),
					E('td', { 'class': 'vscan-mono' }, entry.dhcp_server || '–')
				]));
			}
			else {
				var pkts = entry.packets || 0;
				total += pkts;
				var isUntagged = entry.vid === null;
				rows.push(E('tr', isUntagged ? { 'class': 'vscan-untagged' } : {}, [
					E('td', {}, isUntagged ? _('untagged') : String(entry.vid)),
					E('td', {}, String(pkts)),
					E('td', {}, classChips(entry.classes))
				]));
			}
		});
		if (!isProbe) {
			rows.push(E('tr', { 'class': 'vscan-total' }, [
				E('td', {}, _('Total')),
				E('td', {}, String(total)),
				E('td', {}, '')
			]));
		}

		var summary = isProbe
			? _('%d live VLAN(s)').format(results.length)
			: _('%d VLAN key(s), %d packets').format(results.length, total);
		var head = [
			E('span', {}, _('Results')),
			E('span', { 'class': 'vscan-count' }, summary)
		];
		if (!isProbe) {
			var discovered = results.filter(function (entry) {
				return entry.vid !== null && entry.vid !== undefined;
			}).map(function (entry) {
				return entry.vid;
			});
			if (discovered.length) {
				/* LuCI's createHandlerFn() takes (ctx, fn, ...args). Passing a
				 * bare function makes it return null and silently drops the
				 * click handler. */
				head.push(E('button', {
					'class': 'btn cbi-button',
					'style': 'margin-left:auto',
					'click': ui.createHandlerFn(self, function () {
						return self.probeDiscovered(discovered);
					})
				}, _('Probe these VLANs')));
			}
		}
		return E('div', {}, [
			E('div', { 'class': 'vscan-results-head' }, head),
			E('table', { 'class': 'vscan-table' }, rows)
		]);
	},

	renderJob: function (job) {
		var self = this;

		var actions = [];
		/* Logs have their own tab; this button selects this job there. */
		actions.push(E('button', {
			'class': 'btn cbi-button',
			'click': ui.createHandlerFn(self, function () {
				self.logSelectedId = job.id;
				self.setTab('log');
			})
		}, _('View log')));
		if (job.status == 'running') {
			actions.push(E('button', {
				'class': 'btn cbi-button cbi-button-negative',
				'click': ui.createHandlerFn(self, function () {
					return ctlExec([ 'stop', job.id ]).then(function () {
						return self.refreshJobs();
					});
				})
			}, _('Stop')));
		}
		else {
			actions.push(E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': ui.createHandlerFn(self, function () {
					return askConfirm(
						_('Delete job'),
						_('Really delete job %s and its results?').format(jobTime(job.id)),
						_('Delete')
					).then(function (confirmed) {
						if (!confirmed)
							return;
						return ctlExec([ 'delete', job.id ]).then(function (reply) {
							if (reply && reply.code != 0)
								ui.addNotification(null, E('p', {}, _('Failed to delete the job: %s').format(reply.stdout || reply.code)), 'error');
							return self.refreshJobs();
						});
					});
				})
			}, _('Delete')));
		}

		var head = E('div', { 'class': 'vscan-head' }, [
			E('div', { 'class': 'vscan-badges' }, [
				E('span', { 'class': 'vscan-title' }, _('Job %s').format(jobTime(job.id))),
				statusBadge(job.status),
				E('span', { 'class': 'vscan-tag accent' }, modeText(job.mode)),
				E('span', { 'class': 'vscan-tag' }, job.interface || _('auto-detect'))
			]),
			E('div', { 'class': 'vscan-actions' }, actions)
		]);

		var body = [ head, paramChips(job) ];

		if (job.status == 'running') {
			var percent = progressPercent(job);
			body.push(E('div', { 'class': 'vscan-progress-wrap' }, [
				E('div', { 'class': 'vscan-progress-meta' }, progressText(job) + '  ·  ' + percent + '%'),
				E('div', { 'class': 'vscan-progress' },
					E('div', { 'style': 'width:' + percent + '%' }, ''))
			]));
		}
		else if (job.error) {
			body.push(E('div', { 'class': 'vscan-note' }, _('The scan failed: %s').format(job.error)));
		}
		else if (job.status == 'interrupted') {
			body.push(E('div', { 'class': 'vscan-note' }, _('The scanner process is no longer running; partial results were kept.')));
		}
		else if (job.status == 'failed') {
			body.push(E('div', { 'class': 'vscan-note' }, _('The scan failed - see the run log below for details.')));
		}

		/* A failed job writes an empty results.json. Showing the
		 * "no live VLANs, try a longer wait" advice on top of the real
		 * error would send the user chasing the wrong setting. */
		if (job.results && job.status != 'failed')
			body.push(self.renderResults(job));

		return E('div', { 'class': 'vscan-card status-' + (job.status || 'unknown') }, body);
	},

	refreshJobs: function () {
		var self = this;
		return self.fetchJobs().then(function (jobs) {
			jobs.sort(function (left, right) {
				return (parseInt(right.id, 10) || 0) - (parseInt(left.id, 10) || 0);
			});
			self.jobs = jobs;

			if (self.logTabCount) {
				var running = jobs.filter(function (job) {
					return job.status == 'running';
				}).length;
				self.logTabCount.textContent = String(running || jobs.length);
				self.logTabCount.title = running
					? _('%d running job(s)').format(running)
					: _('%d job(s)').format(jobs.length);
			}

			var container = self.jobsNode;
			if (container) {
				container.innerHTML = '';
				if (!jobs.length) {
					container.appendChild(E('p', { 'class': 'alert-message info' },
						_('No scan jobs yet. Start one above; jobs survive page reloads and LuCI logins until the device reboots.')));
				}
				else {
					jobs.forEach(function (job) {
						container.appendChild(self.renderJob(job));
					});
				}
			}

			/* The log tab follows the same 3s poll as the job list. */
			if (self.activeTab == 'log' && self.logAutoNode && self.logAutoNode.checked)
				self.refreshLog(false);
		});
	},

	applyModeVisibility: function () {
		var self = this;
		var probe = self.modeNode.value == 'probe';
		self.durationRow.style.display = probe ? 'none' : '';
		self.probeRows.forEach(function (row) {
			row.style.display = probe ? '' : 'none';
		});
		self.updateEstimate();
	},

	applyVlanMode: function () {
		var self = this;
		self.vlansCustomNode.style.display =
			self.vlansModeNode.value == 'custom' ? '' : 'none';
		self.updateEstimate();
	},

	/* Show the real cost of a probe before it is started. Each VLAN costs a
	 * full reply window plus a fixed inter-VLAN gap, and sends three frames. */
	updateEstimate: function () {
		var self = this;
		if (!self.vlansEstimateNode || !self.vlansModeNode)
			return;
		var mode = self.vlansModeNode.value;
		var wait = parseInt(self.waitNode.value, 10);
		if (isNaN(wait) || wait < 100)
			wait = 2000;
		var text;
		if (mode === '') {
			text = _('Empty probes only the VLANs already configured on the PON interface. ISP VLAN ids differ by region - run a passive scan first if the service VLAN is unknown.');
		}
		else {
			var count = mode == 'all' ? ALL_VLAN_COUNT
				: (mode == 'common' ? COMMON_VLAN_IDS.length
					: countVlans(self.vlansNode.value));
			if (!count) {
				text = _('Enter VLAN ids or ranges, for example "35,100,1000-1010".');
			}
			else {
				var seconds = (count * wait +
					Math.max(0, count - 1) * PROBE_INTERVAL_MS) / 1000;
				text = _('About %d VLAN(s) · roughly %s · %d discovery frames sent to the OLT.')
					.format(count, durationText(seconds), count * FRAMES_PER_VLAN);
			}
		}
		self.vlansEstimateNode.textContent = text;
	},

	/* Passive results carry the VLANs this specific link really uses. Let the
	 * user carry them straight into an active probe instead of guessing. */
	probeDiscovered: function (vlans) {
		var self = this;
		self.modeNode.value = 'probe';
		self.applyModeVisibility();
		self.vlansModeNode.value = 'custom';
		self.applyVlanMode();
		self.vlansNode.value = vlans.join(',');
		self.updateEstimate();
		self.setTab('jobs');
		if (self.formNode && self.formNode.scrollIntoView)
			self.formNode.scrollIntoView();
	},

	setTab: function (key) {
		var self = this;
		self.activeTab = key;
		self.jobsTab.classList.toggle('active', key == 'jobs');
		self.logTab.classList.toggle('active', key == 'log');
		self.jobsPanel.classList.toggle('active', key == 'jobs');
		self.logPanel.classList.toggle('active', key == 'log');
		if (key == 'log')
			self.refreshLog(true);
	},

	handleRefreshLog: function () {
		var self = this;
		return self.refreshJobs().then(function () {
			self.refreshLog(true);
		});
	},

	refreshLog: function (force) {
		var self = this;
		if (!self.logSelectNode || !self.logPreNode)
			return;

		var jobs = self.jobs || [];
		/* Rebuild the picker only when the job set changes, so an open
		 * dropdown is not reset by every poll tick. */
		var signature = jobs.map(function (job) {
			return job.id + ':' + job.status;
		}).join(',');
		if (self.logOptionsSignature !== signature) {
			self.logOptionsSignature = signature;
			self.logSelectNode.innerHTML = '';
			self.logSelectNode.appendChild(E('option', { value: '' }, _('Latest job (auto)')));
			jobs.forEach(function (job) {
				self.logSelectNode.appendChild(E('option', { value: job.id },
					_('Job %s').format(jobTime(job.id)) + '  ·  ' + statusText(job.status) +
					'  ·  ' + modeText(job.mode)));
			});
		}

		if (self.logSelectedId && !jobs.some(function (job) {
			return job.id == self.logSelectedId;
		}))
			self.logSelectedId = '';
		self.logSelectNode.value = self.logSelectedId || '';

		var selected = null;
		if (self.logSelectedId) {
			selected = jobs.filter(function (job) {
				return job.id == self.logSelectedId;
			})[0] || null;
		}
		else {
			/* "Latest" prefers a running job so a new scan is followed. */
			selected = jobs.filter(function (job) {
				return job.status == 'running';
			})[0] || jobs[0] || null;
		}

		self.logSummaryNode.innerHTML = '';
		self.logParamsNode.innerHTML = '';
		if (selected) {
			self.logSummaryNode.appendChild(E('span', { 'class': 'vscan-title' },
				_('Job %s').format(jobTime(selected.id))));
			self.logSummaryNode.appendChild(statusBadge(selected.status));
			self.logSummaryNode.appendChild(E('span', { 'class': 'vscan-tag accent' },
				modeText(selected.mode)));
			self.logSummaryNode.appendChild(E('span', { 'class': 'vscan-tag' },
				selected.interface || _('auto-detect')));
			self.logParamsNode.appendChild(paramChips(selected));
		}

		var text = normalizeLog(selected && selected.log ? selected.log : '');
		var trimmed = text.replace(/\s+$/, '');
		var allLines = trimmed.split('\n');
		var lineCount = trimmed ? allLines.length : 0;
		var truncated = lineCount > MAX_LOG_LINES;
		var shown = truncated ? allLines.slice(-MAX_LOG_LINES).join('\n') : trimmed;

		if (!shown.trim()) {
			shown = selected
				? _('This job has produced no log output yet.')
				: _('No scan jobs yet. Logs appear here once a scan has been started.');
			self.logPreNode.classList.add('empty');
		}
		else {
			self.logPreNode.classList.remove('empty');
		}

		var pre = self.logPreNode;
		var atBottom = force || (pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24);
		if (self.logLastText !== shown) {
			pre.textContent = shown;
			self.logLastText = shown;
		}
		if (atBottom)
			pre.scrollTop = pre.scrollHeight;

		var meta = _('%d lines · updated %s').format(lineCount, new Date().toLocaleTimeString());
		if (truncated)
			meta += '  ·  ' + _('Showing the last %d lines of a longer log.').format(MAX_LOG_LINES);
		self.logMetaNode.textContent = meta;
	},

	handleStart: function (ev) {
		var self = this;
		var mode = self.modeNode.value;
		var args = [ 'start', mode ];

		if (self.ifaceNode.value)
			args.push('interface=' + self.ifaceNode.value);
		if (mode == 'passive') {
			var duration = parseInt(self.durationNode.value, 10);
			if (isNaN(duration) || duration < 1 || duration > 86400) {
				ui.addNotification(null, E('p', {}, _('Duration must be between 1 and 86400 seconds.')), 'error');
				return;
			}
			args.push('duration=' + duration);
		}
		else {
			var vlanMode = self.vlansModeNode.value;
			var vlans = '';
			if (vlanMode == 'custom') {
				vlans = self.vlansNode.value.trim();
				if (vlans && !/^(all|common|[0-9]+(-[0-9]+)?)(,(all|common|[0-9]+(-[0-9]+)?))*$/i.test(vlans)) {
					ui.addNotification(null, E('p', {}, _('VLAN list must be "35,100,1000-1010", "common" or "all".')), 'error');
					return;
				}
			}
			else if (vlanMode !== '') {
				vlans = vlanMode;
			}
			if (vlans)
				args.push('vlans=' + vlans);

			var mac = self.macNode.value.trim();
			if (mac) {
				if (!/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(mac)) {
					ui.addNotification(null, E('p', {}, _('MAC must be six colon-separated hex octets, e.g. aa:bb:cc:dd:ee:ff.')), 'error');
					return;
				}
				args.push('mac=' + mac);
			}

			var wait = parseInt(self.waitNode.value, 10);
			if (!isNaN(wait) && wait > 0) {
				if (wait < 100 || wait > 60000) {
					ui.addNotification(null, E('p', {}, _('Reply wait must be between 100 and 60000 ms.')), 'error');
					return;
				}
				args.push('probe_wait=' + wait);
			}

			var arp = self.arpNode.value.trim();
			if (arp) {
				if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(arp)) {
					ui.addNotification(null, E('p', {}, _('ARP target must be a valid IPv4 address.')), 'error');
					return;
				}
				args.push('arp_target=' + arp);
			}

			var vendor = self.vendorNode.value.trim();
			if (vendor) {
				if (vendor.length > 255 || !/^[\x20-\x7E]+$/.test(vendor)) {
					ui.addNotification(null, E('p', {}, _('Vendor class must be 1-255 printable ASCII characters.')), 'error');
					return;
				}
				args.push('vendor_class=' + vendor);
			}
		}

		return ctlExec(args).then(function (reply) {
			if (reply && reply.code != 0)
				ui.addNotification(null, E('p', {}, _('Failed to start the scan: %s').format(reply.stderr || reply.stdout || reply.code)), 'error');
			return self.refreshJobs();
		});
	},

	render: function (data) {
		var self = this;
		ensureCss();

		var interfaces = [ '' ];
		if (data[0] && data[0].code == 0) {
			try {
				interfaces = interfaces.concat(JSON.parse(data[0].stdout || '[]'));
			}
			catch (error) { /* fall back to auto-detect only */ }
		}

		var durationRow = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Duration (seconds)')),
			E('div', { 'class': 'cbi-value-field' },
				self.durationNode = E('input', { type: 'number', min: 1, max: 86400, value: 60 }))
		]);

		/* Candidate VLANs are always an explicit choice. An empty selection
		 * means "only VLANs already configured on this device" - ISP VLAN ids
		 * differ by region, so no guessed list is probed implicitly. */
		var vlansRow = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Candidate VLANs')),
			E('div', { 'class': 'cbi-value-field' }, [
				self.vlansModeNode = E('select', {
					'change': function () { self.applyVlanMode(); }
				}, [
					E('option', { value: '' }, _('Configured VLANs only (recommended)')),
					E('option', { value: 'common' }, _('Common ISP VLANs (19 ids)')),
					E('option', { value: 'all' }, _('All VLANs (1-4094)')),
					E('option', { value: 'custom' }, _('Custom list…'))
				]),
				self.vlansCustomNode = E('div', { 'style': 'margin-top:6px' },
					self.vlansNode = E('input', {
						type: 'text',
						placeholder: '130,1000-1010',
						'keyup': function () { self.updateEstimate(); }
					})),
				self.vlansEstimateNode = E('div', { 'class': 'cbi-value-description' })
			])
		]);

		var macRow = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Probe source MAC')),
			E('div', { 'class': 'cbi-value-field' }, [
				self.macNode = E('input', {
					type: 'text',
					placeholder: 'aa:bb:cc:dd:ee:ff'
				}),
				E('div', { 'class': 'cbi-value-description' },
					_('Leave empty to use the PON interface MAC. If the ISP only answers the MAC registered for a service VLAN, enter that interface MAC here.'))
			])
		]);

		var waitRow = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Reply wait (ms)')),
			E('div', { 'class': 'cbi-value-field' }, [
				self.waitNode = E('input', {
					type: 'number', min: 100, max: 60000, value: 2000,
					'change': function () { self.updateEstimate(); },
					'keyup': function () { self.updateEstimate(); }
				}),
				E('div', { 'class': 'cbi-value-description' },
					_('How long to wait for replies on each VLAN. Increase this if the DHCP server is slow; probing "all" VLANs takes roughly this long per VLAN.'))
			])
		]);

		var arpRow = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('ARP target')),
			E('div', { 'class': 'cbi-value-field' }, [
				self.arpNode = E('input', { type: 'text', value: '192.168.1.1' }),
				E('div', { 'class': 'cbi-value-description' },
					_('IP address used in the ARP probe. A matching ARP reply reveals the gateway address.'))
			])
		]);

		var vendorRow = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Vendor class (option 60)')),
			E('div', { 'class': 'cbi-value-field' }, [
				self.vendorNode = E('input', {
					type: 'text',
					placeholder: 'MSFT 5.0'
				}),
				E('div', { 'class': 'cbi-value-description' },
					_('Optional DHCP option 60. Some ISPs only answer a DISCOVER carrying their expected vendor string (for example "MSFT 5.0" or "dslforum.org").'))
			])
		]);

		var probeRows = [ vlansRow, macRow,
			E('div', { 'class': 'cbi-value' },
				E('div', { 'class': 'cbi-value-field' },
					E('div', { 'class': 'vscan-section-title' }, _('Probe options')))),
			waitRow, arpRow, vendorRow ];

		var scanForm = E('div', { 'class': 'cbi-section' }, [
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Interface')),
				E('div', { 'class': 'cbi-value-field' }, [
					self.ifaceNode = E('select', {}, interfaces.map(function (name) {
						return E('option', { value: name }, name || _('auto-detect'));
					})),
					E('div', { 'class': 'cbi-value-description' },
						_('Leave empty to auto-detect the PON interface (found via /sys/class/net/*/xpon, typically pon0).'))
				])
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Mode')),
				E('div', { 'class': 'cbi-value-field' },
				self.modeNode = E('select', {
					'change': function () { self.applyModeVisibility(); }
				}, [
						E('option', { value: 'passive' }, _('Passive listen (no packets sent)')),
						E('option', { value: 'probe' }, _('Probe (discovery frames on candidate VLANs)'))
					]))
			]),
			durationRow
		].concat(probeRows).concat([
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }),
				E('div', { 'class': 'cbi-value-field' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(self, 'handleStart')
					}, _('Start scan')),
					E('div', { 'class': 'vscan-hint' },
						_('VLAN ids reported as untagged (null) are frames without an 802.1Q tag.'))
				])
			])
		]));

		/* Two plain panels with a lightweight tab bar: no dependency on the
		 * CBI tab machinery, and the neutral colours work in both themes. */
		var tabs = E('div', { 'class': 'vscan-tabs' }, [
			self.jobsTab = E('button', {
				'class': 'vscan-tab active', type: 'button',
				'click': function () { self.setTab('jobs'); }
			}, _('Scan jobs')),
			self.logTab = E('button', {
				'class': 'vscan-tab', type: 'button',
				'click': function () { self.setTab('log'); }
			}, [
				_('Run log'),
				self.logTabCount = E('span', { 'class': 'vscan-tab-count' }, '0')
			])
		]);

		self.jobsPanel = E('div', { 'class': 'vscan-panel active' }, [
			scanForm,
			E('h3', {}, _('Scan jobs')),
			self.jobsNode = E('div', {})
		]);

		self.logPanel = E('div', { 'class': 'vscan-panel' }, [
			E('div', { 'class': 'vscan-card' }, [
				E('div', { 'class': 'vscan-toolbar' }, [
					E('label', {}, _('Job')),
					self.logSelectNode = E('select', {
						'change': function (ev) {
							self.logSelectedId = ev.target.value;
							self.refreshLog(true);
						}
					}),
					E('label', {}, [
						self.logAutoNode = E('input', { type: 'checkbox', checked: 'checked' }),
						_('Auto refresh')
					]),
					E('button', {
						'class': 'btn cbi-button',
						'click': ui.createHandlerFn(self, 'handleRefreshLog')
					}, _('Refresh'))
				]),
				self.logSummaryNode = E('div', { 'class': 'vscan-log-summary' }),
				self.logParamsNode = E('div', {}),
				self.logPreNode = E('pre', { 'class': 'vscan-log-pre' }),
				self.logMetaNode = E('div', { 'class': 'vscan-log-meta' })
			])
		]);

		var root = E('div', {}, [
			E('h2', {}, _('VLAN Scan')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Discover which 802.1Q VLAN ids carry traffic on the PON uplink. Passive listening never transmits anything; probing sends discovery frames only (ARP request, PPPoE PADI, DHCP DISCOVER) and never binds a lease or a session.')),
			tabs,
			self.jobsPanel,
			self.logPanel
		]);

		self.activeTab = 'jobs';
		self.jobs = [];
		self.jobCache = {};
		self.logSelectedId = '';
		self.logOptionsSignature = null;
		self.logLastText = null;
		self.logAutoNode.checked = true;
		self.durationRow = durationRow;
		self.probeRows = probeRows;
		self.formNode = scanForm;
		self.applyModeVisibility();
		self.applyVlanMode();

		self.refreshJobs();
		poll.add(L.bind(self.refreshJobs, self), 3);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
