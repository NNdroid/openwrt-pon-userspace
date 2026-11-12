// SPDX-License-Identifier: Apache-2.0

'use strict';
'require fs';
'require poll';
'require dom';
'require ui';
'require view';

var CTL = '/usr/libexec/vlanscan-ctl';

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
					fs.read(base + '/job.json').catch(function () { return null; }),
					fs.read(base + '/results.json').catch(function () { return null; })
				]).then(function (files) {
					var job = {};
					try {
						job = JSON.parse((files[0] && files[0].data) || '{}');
					}
					catch (error) { /* job.json not written yet */ }
					job.id = entry.id;
					job.status = entry.status;
					if (files[1] && files[1].data) {
						try {
							job.results = JSON.parse(files[1].data);
						}
						catch (error) { /* partial write, retry next poll */ }
					}
					return job;
				});
			}));
		});
	},

	renderResults: function (job) {
		var results = job.results;
		if (!results || !results.length)
			return E([]);

		if (job.mode == 'probe') {
			var rows = results.map(function (entry) {
				return E('tr', {}, [
					E('td', {}, String(entry.vid)),
					E('td', {}, entry.pppoe ? _('yes (PADO)') : '–'),
					E('td', {}, entry.gateway || '–'),
					E('td', {}, entry.dhcp_offer || '–'),
					E('td', {}, entry.dhcp_server || '–')
				]);
			});
			return E('table', { 'class': 'table table-condensed' }, [
				E('tr', { 'class': 'tr-table-titles' }, [
					E('th', {}, _('VLAN')),
					E('th', {}, _('PPPoE')),
					E('th', {}, _('Gateway (ARP)')),
					E('th', {}, _('DHCP offer')),
					E('th', {}, _('DHCP server'))
				]),
				rows
			]);
		}

		var rows = results.map(function (entry) {
			var classes = Object.keys(entry.classes || {}).sort().map(function (name) {
				return '%s=%d'.format(name, entry.classes[name]);
			}).join(', ');
			return E('tr', {}, [
				E('td', {}, entry.vid === null ? _('untagged') : String(entry.vid)),
				E('td', {}, String(entry.packets)),
				E('td', {}, classes)
			]);
		});
		return E('table', { 'class': 'table table-condensed' }, [
			E('tr', { 'class': 'tr-table-titles' }, [
				E('th', {}, _('VLAN')),
				E('th', {}, _('Packets')),
				E('th', {}, _('Traffic classes'))
			]),
			rows
		]);
	},

	renderJob: function (job) {
		var self = this;
		var body = [
			E('strong', {}, _('Job %s').format(jobTime(job.id))),
			' ',
			statusBadge(job.status),
			E('span', { 'class': 'label label-default' }, job.mode || '?'),
			E('span', { 'class': 'label label-default' }, job.interface || '?')
		];

		if (job.status == 'running')
			body = body.concat([
				' ',
				E('em', {}, progressText(job)),
				E('button', {
					'class': 'btn cbi-button cbi-button-negative',
					'style': 'margin-left: 1em; float: right',
					'click': ui.createHandlerFn(function () {
						return ctlExec([ 'stop', job.id ]).then(function () {
							return self.refreshJobs();
						});
					})
				}, _('Stop'))
			]);
		else
			body = body.concat([
				job.status == 'interrupted'
					? E('em', {}, ' ' + _('The scanner process is no longer running; partial results were kept.'))
					: (job.status == 'failed'
						? E('em', {}, ' ' + _('The scan failed - see the system log for details.'))
						: null),
				E('button', {
					'class': 'btn cbi-button cbi-button-remove',
					'style': 'margin-left: 1em; float: right',
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
				}, _('Delete'))
			]);

		if (job.results)
			body = body.concat([ E('div', { 'style': 'margin-top: .5em' }, this.renderResults(job)) ]);

		return E('div', { 'class': 'cbi-section', 'style': 'margin-bottom: 1em' }, [
			E('div', { 'class': 'cbi-section-descr' }, body)
		]);
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
