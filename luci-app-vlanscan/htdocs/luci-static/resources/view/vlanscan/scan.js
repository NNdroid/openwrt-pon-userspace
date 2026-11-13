// SPDX-License-Identifier: Apache-2.0

'use strict';
'require fs';
'require poll';
'require dom';
'require ui';
'require view';

var CTL = '/usr/libexec/vlanscan-ctl';

/* Beautified styles (injected once into <head>). */
var CSS = [
	'/* VLAN Scan beautified styles */',
	'.vscan-card{background:#fff;border:1px solid #e6e6e6;border-radius:10px;padding:14px 16px;margin-bottom:14px;box-shadow:0 1px 2px rgba(0,0,0,.04);}',
	'.vscan-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;}',
	'.vscan-badges{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;}',
	'.vscan-title{font-weight:600;font-size:15px;color:#222;}',
	'.vscan-meta{color:#8a8a8a;font-size:12.5px;margin:8px 0 4px;}',
	'.vscan-actions{display:inline-flex;gap:6px;}',
	'.vscan-tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11.5px;background:#f0f2f5;color:#555;}',
	'.vscan-results-head{font-weight:600;font-size:13px;color:#444;margin:12px 0 4px;}',
	'.vscan-table{width:100%;border-collapse:collapse;margin-top:4px;font-size:13px;}',
	'.vscan-table th{text-align:left;background:#f7f8fa;padding:7px 10px;border-bottom:2px solid #e6e6e6;color:#555;font-weight:600;}',
	'.vscan-table td{padding:6px 10px;border-bottom:1px solid #f0f0f0;vertical-align:top;}',
	'.vscan-untagged td:first-child{font-weight:600;color:#b5650a;}',
	'.vscan-total td{font-weight:600;background:#fafbfc;border-top:2px solid #e6e6e6;}',
	'.vscan-chip{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11.5px;margin:1px 4px 1px 0;white-space:nowrap;}',
	'.vscan-chip.pppoe{background:#e3f0ff;color:#1a5fb4;}',
	'.vscan-chip.arp{background:#f0f0f0;color:#555;}',
	'.vscan-chip.dhcp{background:#e6f7ec;color:#1a7f43;}',
	'.vscan-chip.ipv4{background:#e8f4f8;color:#0b6e8f;}',
	'.vscan-chip.ipv6{background:#f0e9fb;color:#6a3fb5;}',
	'.vscan-chip.igmp{background:#fdeede;color:#b5650a;}',
	'.vscan-chip.other{background:#f3f3f3;color:#666;}',
	'.vscan-empty{color:#999;font-style:italic;padding:6px 0;}',
	'.vscan-note{color:#c0392b;font-size:12.5px;}'
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

function statusBadge(status) {
	var classes = {
		running: 'label label-success',
		completed: 'label label-info',
		stopped: 'label label-warning',
		interrupted: 'label label-warning',
		failed: 'label label-danger'
	};
	return E('span', { 'class': classes[status] || 'label label-default' }, status);
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

/* Map a traffic class name to a colour class for the chip. */
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

return view.extend({
	load: function () {
		return Promise.all([
			ctlExec([ 'interfaces' ]),
			ctlExec([ 'list' ])
		]);
	},

	fetchJobs: function () {
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
			return Promise.all(entries.map(function (entry) {
				var base = '/tmp/vlanscan/' + entry.id;
				return Promise.all([
					readText(base + '/job.json'),
					readText(base + '/results.json')
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
							job.results = JSON.parse(texts[1]);
						}
						catch (error) { /* partial write, retry next poll */ }
					}
					return job;
				});
			}));
		});
	},

	/* One-line summary of the parameters actually used for the scan. */
	paramLine: function (job) {
		var parts = [
			_('Mode') + ': ' + modeText(job.mode),
			_('Interface') + ': ' + (job.interface || _('auto-detect'))
		];
		if (job.mode == 'probe') {
			var vlans = (job.params && job.params.vlans) ? job.params.vlans.join(', ') : _('all');
			parts.push(_('VLANs') + ': ' + vlans);
		}
		else {
			var dur = (job.params && job.params.duration) ? job.params.duration : '?';
			parts.push(_('Duration') + ': ' + dur + ' s');
		}
		return E('div', { 'class': 'vscan-meta' }, parts.join('   ·   '));
	},

	renderResults: function (job) {
		var results = job.results;
		if (!results || !results.length)
			return E('div', { 'class': 'vscan-empty' }, _('No packets captured during this scan window.'));

		if (job.mode == 'probe') {
			var prows = results.map(function (entry) {
				return E('tr', {}, [
					E('td', {}, String(entry.vid)),
					E('td', {}, entry.pppoe ? _('yes (PADO)') : '–'),
					E('td', {}, entry.gateway || '–'),
					E('td', {}, entry.dhcp_offer || '–'),
					E('td', {}, entry.dhcp_server || '–')
				]);
			});
			return E('div', {}, [
				E('div', { 'class': 'vscan-results-head' }, _('Results')),
				E('table', { 'class': 'vscan-table' }, [
					E('tr', { 'class': 'vscan-thead' }, [
						E('th', {}, _('VLAN')),
						E('th', {}, _('PPPoE')),
						E('th', {}, _('Gateway (ARP)')),
						E('th', {}, _('DHCP offer')),
						E('th', {}, _('DHCP server'))
					]),
					prows
				])
			]);
		}

		var total = 0;
		var rows = results.map(function (entry) {
			var pkts = entry.packets || 0;
			total += pkts;
			var isUntagged = entry.vid === null;
			return E('tr', isUntagged ? { 'class': 'vscan-untagged' } : {}, [
				E('td', {}, isUntagged ? _('untagged') + ' (null)' : String(entry.vid)),
				E('td', {}, String(pkts)),
				E('td', {}, classChips(entry.classes))
			]);
		});
		rows.push(E('tr', { 'class': 'vscan-total' }, [
			E('td', {}, _('Total')),
			E('td', {}, String(total)),
			E('td', {}, '')
		]));
		return E('div', {}, [
			E('div', { 'class': 'vscan-results-head' }, _('Results')),
			E('table', { 'class': 'vscan-table' }, [
				E('tr', { 'class': 'vscan-thead' }, [
					E('th', {}, _('VLAN')),
					E('th', {}, _('Packets')),
					E('th', {}, _('Traffic classes'))
				]),
				rows
			])
		]);
	},

	renderJob: function (job) {
		var self = this;

		var actions = [];
		if (job.status == 'running') {
			actions.push(E('button', {
				'class': 'btn cbi-button cbi-button-negative',
				'click': ui.createHandlerFn(function () {
					return ctlExec([ 'stop', job.id ]).then(function () {
						return self.refreshJobs();
					});
				})
			}, _('Stop')));
		}
		else {
			actions.push(E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': ui.createHandlerFn(function () {
					return ui.confirm(_('Really delete job %s and its results?').format(jobTime(job.id)), _('Delete'))
						.then(function (confirmed) {
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
				E('span', { 'class': 'vscan-tag' }, modeText(job.mode)),
				E('span', { 'class': 'vscan-tag' }, job.interface || _('auto-detect'))
			]),
			E('div', { 'class': 'vscan-actions' }, actions)
		]);

		var body = [ head, self.paramLine(job) ];

		if (job.status == 'running')
			body.push(E('div', { 'class': 'vscan-meta' }, progressText(job)));
		else if (job.status == 'interrupted')
			body.push(E('div', { 'class': 'vscan-note' }, _('The scanner process is no longer running; partial results were kept.')));
		else if (job.status == 'failed')
			body.push(E('div', { 'class': 'vscan-note' }, _('The scan failed - see the system log for details.')));

		if (job.results)
			body.push(self.renderResults(job));

		return E('div', { 'class': 'vscan-card' }, body);
	},

	refreshJobs: function () {
		var self = this;
		return self.fetchJobs().then(function (jobs) {
			var container = self.jobsNode;
			if (!container)
				return;
			container.innerHTML = '';
			if (!jobs.length) {
				container.appendChild(E('p', { 'class': 'alert-message info' },
					_('No scan jobs yet. Start one above; jobs survive page reloads and LuCI logins until the device reboots.')));
				return;
			}
			jobs.sort(function (left, right) {
				return (parseInt(right.id, 10) || 0) - (parseInt(left.id, 10) || 0);
			});
			jobs.forEach(function (job) {
				container.appendChild(self.renderJob(job));
			});
		});
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
			var vlans = self.vlansNode.value.trim();
			if (vlans && !/^(all|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)$/.test(vlans)) {
				ui.addNotification(null, E('p', {}, _('VLAN list must be "35,100,1000-1010" or "all".')), 'error');
				return;
			}
			if (vlans)
				args.push('vlans=' + vlans);
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

		var root = E('div', {}, [
			E('h2', {}, _('VLAN Scan')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Discover which 802.1Q VLAN ids carry traffic on the PON uplink. Passive listening never transmits anything; probing sends discovery frames only (ARP request, PPPoE PADI, DHCP DISCOVER) and never binds a lease or a session.')),
			E('div', { 'class': 'cbi-section' }, [
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
							'change': function (ev) {
								self.durationRow.style.display = ev.target.value == 'passive' ? '' : 'none';
								self.vlansRow.style.display = ev.target.value == 'probe' ? '' : 'none';
							}
						}, [
							E('option', { value: 'passive' }, _('Passive listen (no packets sent)')),
							E('option', { value: 'probe' }, _('Probe (discovery frames on candidate VLANs)'))
						]))
				]),
				self.durationRow = E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Duration (seconds)')),
					E('div', { 'class': 'cbi-value-field' },
						self.durationNode = E('input', { type: 'number', min: 1, max: 86400, value: 60 }))
				]),
				self.vlansRow = E('div', { 'class': 'cbi-value', 'style': 'display: none' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Candidate VLANs')),
					E('div', { 'class': 'cbi-value-field' }, [
						self.vlansNode = E('input', {
							type: 'text',
							placeholder: '35,100,1000-1010'
						}),
						E('div', { 'class': 'cbi-value-description' },
							_('Comma separated ids or ranges, "all" for 1-4094. Empty uses a short list of common ISP VLANs.'))
					])
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }),
					E('div', { 'class': 'cbi-value-field' },
						E('button', {
							'class': 'btn cbi-button cbi-button-apply',
							'click': ui.createHandlerFn(self, 'handleStart')
						}, _('Start scan')))
				])
			]),
			E('h3', {}, _('Scan jobs')),
			self.jobsNode = E('div', {})
		]);

		self.refreshJobs();
		poll.add(L.bind(self.refreshJobs, self), 3);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
