'use strict';
'require form';
'require fs';
'require ui';
'require view';


return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load() {
		// Read known_hosts directly and split into lines. Using fs.read() + split
		// instead of fs.lines() keeps this robust across LuCI versions and never
		// rejects: an empty/missing file simply yields no rows.
		return Promise.all([
			L.resolveDefault(fs.read('/root/.ssh/known_hosts'), '').then(function (s) {
				return s.split('\n')
					.map(function (l) { return l.trim(); })
					.filter(function (l) { return l.length > 0; });
			})
		]);
	},

	render([knownHosts]) {
		let m, s;

		m = new form.Map('sshtunnel', _('SSH Tunnels'),
			_('This configures <a %s>SSH Tunnels</a>.')
				.format('href="https://openwrt.org/docs/guide-user/services/ssh/sshtunnel"')
		);

		s = m.section(form.Section);
		s.render = L.bind(_renderKnownHosts, this, knownHosts);

		return m.render();
	},
});

function _renderKnownHosts(knownHosts) {
	const rows = _splitKnownHosts(knownHosts);
	const trs = [];
	for (let i = 0; i < rows.length; i++) {
		trs.push(E('tr', {'class': 'tr'}, [
			E('td', {'class': 'td'}, [rows[i][0]]),
			E('td', {'class': 'td'}, [rows[i][1]])
		]));
	}

	const table = E('table', {'class': 'table cbi-section-table', 'id': 'known_hosts'}, [
		E('tr', {'class': 'tr table-titles'}, [
			E('th', {'class': 'th'}, _('Hostname')),
			E('th', {'class': 'th'}, _('Public Key'))
		])
	].concat(trs));

	return E('div', {'class': 'cbi-section cbi-tblsection'}, [
		E('h3', _('Known hosts ')),
		E('div', {'class': 'cbi-section-descr'},
			_('Keys of SSH servers found in %s.').format('<code>/root/.ssh/known_hosts</code>')
		),
		table
	]);
}

function _splitKnownHosts(knownHosts) {
	const knownHostsMap = [];
	for (let kh of knownHosts) {
		const sp = kh.indexOf(' ');
		if (sp < 0) {
			continue;
		}
		const hostname = kh.substring(0, sp);
		const pub = kh.substring(sp + 1);
		knownHostsMap.push([hostname, E('small', {}, [E('code', {}, pub)])]);
	}
	return knownHostsMap;
}
