'use strict';
'require form';
'require fs';
'require uci';
'require ui';
'require view';
'require view.sshtunnel.status as status';

return view.extend({
	load() {
		return Promise.all([
			uci.load('sshtunnel'),
			status.load()
		]);
	},

	/* load() resolves to an array; render() receives the whole array as one
	 * argument. Index it explicitly instead of destructuring. */
	render(data) {
		const statusData = data[1];
		let m, s, o;

		m = new form.Map('sshtunnel', _('SSH Tunnels'),
			_('This configures <a %s>SSH Tunnels</a>.')
				.format('href="https://openwrt.org/docs/guide-user/services/ssh/sshtunnel"') + '<br />' +
			_('Four forwarding types are available. Each tunnel is bound to one server section; several tunnels can share a single SSH connection.')
		);

		s = m.section(form.GridSection, 'tunnelR', _('Remote Tunnels'),
			_('Forward a port on the remote host to a service on the local host.') + '<br />' +
			_('Equivalent to ssh -R: a port on the remote host is forwarded to a service reachable from this device.')
		);
		s.anonymous = true;
		s.addremove = true;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('Disabled sections remain in the configuration but are not started.'));
		o.default = '1';

		o = _addServerOption(s);

		o = s.option(form.Value, 'remoteaddress', _('Remote address'),
			_('Bind IP address e.g. <code>192.168.1.1</code> or hostname e.g. <code>localhost</code>.') + '<br/>' +
			_('<code>*</code> means to listen all interfaces <b>including public</b>.') + '<br/>' +
			_('Binding to * requires GatewayPorts on the remote SSH server, otherwise only loopback is reachable.')
		);
		o.datatype = 'or(host, "*")';
		o.default = '*';
		o.rmempty = false;

		o = s.option(form.Value, 'remoteport', _('Remote port'),
			_('TCP port opened on the remote host.'));
		o.placeholder = '80';
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.Value, 'localaddress', _('Local address'),
			_('Bind IP address e.g. <code>192.168.1.1</code> or hostname e.g. <code>localhost</code>.') + '<br/>' +
			_('Destination host as seen from this device.')
		);
		o.datatype = 'host';
		o.default = 'localhost';
		o.rmempty = false;

		o = s.option(form.Value, 'localport', _('Local port'),
			_('TCP port of the destination service on this device or on the given local address.'));
		o.datatype = 'port';
		o.placeholder = '80';
		o.rmempty = false;


		s = m.section(form.GridSection, 'tunnelL', _('Local Tunnels'),
			_('Forward a port on the local host to a service on the remote host.') + '<br />' +
			_('Equivalent to ssh -L: a port on this device is forwarded to a service reachable from the remote host.')
		);
		s.anonymous = true;
		s.addremove = true;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('Disabled sections remain in the configuration but are not started.'));
		o.default = '1';

		o = _addServerOption(s);

		o = s.option(form.Value, 'localaddress', _('Local address'),
			_('Bind IP address e.g. <code>192.168.1.1</code> or hostname e.g. <code>localhost</code>.') + '<br/>' +
			_('<code>*</code> means to listen all interfaces <b>including public</b>.') + '<br/>' +
			_('Use 127.0.0.1 or localhost to accept connections from this device only.')
		);
		o.datatype = 'or(host, "*")';
		o.placeholder = '192.168.1.1'; // not the default * public iface because a user must explicitly configure it
		o.rmempty = false;

		o = s.option(form.Value, 'localport', _('Local port'),
			_('TCP port opened on this device.'));
		o.datatype = 'port';
		o.placeholder = '80';
		o.rmempty = false;

		o = s.option(form.Value, 'remoteaddress', _('Remote address'),
			_('Bind IP address e.g. <code>192.168.1.1</code> or hostname e.g. <code>localhost</code>.') + '<br/>' +
			_('Destination host as seen from the remote SSH server.')
		);
		o.datatype = 'host';
		o.default = 'localhost';
		o.rmempty = false;

		o = s.option(form.Value, 'remoteport', _('Remote port'),
			_('TCP port of the destination service on the remote side.'));
		o.datatype = 'port';
		o.default = '80';
		o.rmempty = false;


		s = m.section(form.GridSection, 'tunnelD', _('Dynamic Tunnels'),
			_('SOCKS proxy via remote host.') + '<br />' +
			_('Equivalent to ssh -D: a SOCKS5 proxy is opened on this device and exits through the remote host.')
		);
		s.anonymous = true;
		s.addremove = true;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('Disabled sections remain in the configuration but are not started.'));
		o.default = '1';

		o = _addServerOption(s);

		o = s.option(form.Value, 'localaddress', _('Local address'),
			_('Bind IP address e.g. <code>192.168.1.1</code> or hostname e.g. <code>localhost</code>.') + '<br/>' +
			_('<code>*</code> means to listen all interfaces <b>including public</b>.') + '<br/>' +
			_('Clients must be configured to use a SOCKS5 proxy at this address and port.')
		);
		o.datatype = 'or(host, "*")';
		o.placeholder = '192.168.1.1'; // not the default * public iface because a user must explicitly configure it
		o.rmempty = false;

		o = s.option(form.Value, 'localport', _('Local port'),
			_('TCP port on which the SOCKS5 proxy listens.'));
		o.datatype = 'port';
		o.default = '1080';
		o.rmempty = false;


		s = m.section(form.GridSection, 'tunnelW', _('VPN Tunnels'),
			_('Configure TUN/TAP devices for VPN tunnels.') + '<br />' +
			_('Equivalent to ssh -w: an IP or Ethernet tunnel is built over SSH. Requires root on both ends and a tun/tap device.')
		);
		s.anonymous = true;
		s.addremove = true;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('Disabled sections remain in the configuration but are not started.'));
		o.default = '1';

		o = _addServerOption(s);

		o = s.option(form.ListValue, 'vpntype', _('VPN type'),
			_('TUN carries IP packets (point-to-point), TAP carries Ethernet frames (bridging).')
		);
		o.value('point-to-point', 'TUN (point-to-point)');
		o.value('ethernet', 'TAP (ethernet)');
		o.default = 'point-to-point';

		o = s.option(form.Value, 'localdev', _('Local dev'),
			_('Tunnel device number, or any to let the SSH server choose a free device.'));
		o.default = 'any';
		o.datatype = 'or("any", min(0))';
		o.rmempty = false;

		o = s.option(form.Value, 'remotedev', _('Remote dev'),
			_('Tunnel device number, or any to let the SSH server choose a free device.'));
		o.default = 'any';
		o.datatype = 'or("any", min(0))';
		o.rmempty = false;

		return m.render().then(function (mapNode) {
			return E('div', {}, [
				status.renderSummary(statusData),
				mapNode,
				status.renderForwardingTable(statusData)
			]);
		});
	},
});

function _addServerOption(s) {
	const o = s.option(form.ListValue, 'server', _('Server'),
		_('Server section whose SSH connection carries this tunnel.'));
	o.datatype = 'uciname';
	o.rmempty = false;
	uci.sections('sshtunnel', 'server', function (s, sectionName) {
		o.value(sectionName, s.hostname ? '%s (%s)'.format(sectionName, s.hostname) : sectionName);
	});
	return o;
}
