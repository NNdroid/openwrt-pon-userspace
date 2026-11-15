'use strict';
'require view';
'require view.sshtunnel.status as status';

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load() {
		return status.load();
	},

	render(data) {
		return E('div', {}, [
			E('h2', {}, [ _('SSH Tunnels Status') ]),
			E('div', { 'class': 'cbi-map-descr' },
				_('Runtime information about the sshtunnel service, its forwarding instances and recent log entries.')),
			status.renderFull(data)
		]);
	}
});
