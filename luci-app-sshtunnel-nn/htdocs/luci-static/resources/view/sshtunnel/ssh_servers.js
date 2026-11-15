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
			L.resolveDefault(fs.list('/root/.ssh/'), []).then(function (entries) {
				return _findAllPossibleIdKeys(entries);
			}),
			status.load()
		]);
	},

	/* load() resolves to an array, so render() receives that whole array as
	 * its first argument. Use explicit indexes - destructuring here would
	 * unpack the array instead. */
	render(data) {
		const sshKeyNames = data[0];
		const statusData = data[1];
		if (sshKeyNames.length === 0) {
			ui.addNotification(null, E('p', _('No SSH keys found, <a %s>generate a new one</a>').format('href="./ssh_keys"')), 'warning');
		}

		let m, s, o;

		m = new form.Map('sshtunnel', _('SSH Tunnels'),
			_('This configures <a %s>SSH Tunnels</a>.')
				.format('href="https://openwrt.org/docs/guide-user/services/ssh/sshtunnel"') + '<br />' +
			_('Each server section defines one SSH connection. Tunnels refer to a server by name and share that connection.')
		);

		s = m.section(form.GridSection, 'server', _('Servers'));
		s.anonymous = false;
		s.addremove = true;
		s.nodescriptions = true;

		o = s.tab('general', _('General Settings'));
		o = s.tab('advanced', _('Advanced Settings'));

		o = s.taboption('general', form.Value, 'hostname', _('Hostname'),
			_('DNS name or IP address of the remote SSH server. It is also used to look up the host key in the known_hosts file.')
		);
		o.placeholder = 'example.com';
		o.datatype = 'host';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'port', _('Port'),
			_('SSH port on the remote host. Defaults to 22 when left empty.')
		);
		o.placeholder = '22';
		o.datatype = 'port';

		o = s.taboption('general', form.Value, 'user', _('User'),
			_('Login name on the remote host. Defaults to root; root is required for TUN/TAP VPN tunnels.')
		);
		o.default = 'root';

		o = s.taboption('general', form.Value, 'IdentityFile', _('Identity Key'),
			_('Private key file with authentication identity.') + '<br />' +
			_('If not specified then a default will be used.') + '<br />' +
			_('For Dropbear %s').format('<code>id_dropbear</code>') + '<br />' +
			_('For OpenSSH %s').format('<code>id_rsa, id_ed25519, id_ecdsa</code>') + '<br />' +
			_('The key must be passphrase-free and readable by the SSH client selected on this device.') +
			_manSshConfig('IdentityFile') +
			_discoveredKeysHint(sshKeyNames)
		);
		o.placeholder = '/root/.ssh/id_ed25519';
		o.optional = true;


		o = s.taboption('advanced', form.ListValue, 'LogLevel', _('Log level'),
			_('Verbosity of the SSH client log.') + '<br />' +
			_('OpenSSH only; Dropbear ignores this option.')
		);
		o.value('QUIET', 'QUIET');
		o.value('FATAL', 'FATAL');
		o.value('ERROR', 'ERROR');
		o.value('INFO', 'INFO');
		o.value('VERBOSE', 'VERBOSE');
		o.value('DEBUG', 'DEBUG');
		o.value('DEBUG2', 'DEBUG2');
		o.value('DEBUG3', 'DEBUG3');
		o.default = 'INFO';
		o.modalonly = true;

		o = s.taboption('advanced', form.ListValue, 'Compression', _('Use compression'),
			_('Compression may be useful on slow connections.') + '<br />' +
			_('Supported by both OpenSSH and Dropbear.') +
			_manSshConfig('Compression')
		);
		o.value('yes', _('Yes'));
		o.value('no', _('No'));
		o.default = 'no';
		o.modalonly = true;

		o = s.taboption('advanced', form.Value, 'retrydelay', _('Retry delay'),
			_('Delay after a connection failure before trying to reconnect.') + '<br />' +
			_('Seconds to wait before reconnecting after the client exits. Minimum 1; the service uses 60 when unset.')
		);
		o.placeholder = '10';
		o.default = '10';
		o.datatype = 'uinteger';
		o.optional = true;
		o.modalonly = true;

		o = s.taboption('advanced', form.Value, 'ServerAliveCountMax', _('Server keep alive attempts'),
			_('The number of server alive messages which may be sent before SSH disconnects from the server.') + '<br />' +
			_('OpenSSH only; Dropbear ignores this option.') +
			_manSshConfig('ServerAliveCountMax')
		);
		o.placeholder = '3';
		o.datatype = 'uinteger';
		o.optional = true;
		o.modalonly = true;

		o = s.taboption('advanced', form.Value, 'ServerAliveInterval', _('Server keep alive interval (seconds)'),
			_('Send a keepalive probe after this many seconds of inactivity.') + '<br />' +
			_('Supported by both OpenSSH and Dropbear.') +
			_manSshConfig('ServerAliveInterval')
		);
		o.optional = true;
		o.default = '60';
		o.datatype = 'uinteger';
		o.modalonly = true;

		o = s.taboption('advanced', form.ListValue, 'CheckHostIP', _('Check host IP'),
			_('Check the host IP address in the %s file.').format('<code>known_hosts</code>') + '<br />' +
			_('This allows SSH to detect whether a host key changed due to DNS spoofing.') + '<br />' +
			_('OpenSSH only; Dropbear ignores this option.') +
			_manSshConfig('CheckHostIP')
		);
		o.value('yes', _('Yes'));
		o.value('no', _('No'));
		o.default = 'no';
		o.modalonly = true;

		o = s.taboption('advanced', form.ListValue, 'StrictHostKeyChecking', _('Strict host key checking'),
			_('Refuse to connect to hosts whose host key has changed.') + '<br />' +
			_('For Dropbear, accept-new and no are translated to -y and -yy.') +
			_manSshConfig('StrictHostKeyChecking')
		);
		o.value('accept-new', _('Accept new and check if not changed'));
		o.value('yes', _('Yes'));
		o.value('no', _('No'));
		o.default = 'accept-new';
		o.modalonly = true;

		o = s.taboption('advanced', form.Value, 'ProxyCommand', _('Proxy tunnel command'),
			_('The command to use to connect to the server.') + '<br />' +
			_('For example, the following command would connect via an HTTP proxy:') + '<br />' +
			'<code>ncat --proxy-type http --proxy-auth alice:secret --proxy 192.168.1.2:8080 %h %p</code>' + '<br />' +
			_('Passed as -o ProxyCommand to both clients. Leave empty for a direct connection.') +
			_manSshConfig('ProxyCommand')
		);
		o.modalonly = true;

		return m.render().then(function (mapNode) {
			return E('div', {}, [ status.renderSummary(statusData), mapNode ]);
		});
	},
});

function _findAllPossibleIdKeys(entries) {
	const sshKeyNames = new Set();
	const fileNames = entries.filter(item => item.type === 'file').map(item => item.name);
	for (let fileName of fileNames) {
		// a key file should have a corresponding .pub file
		if (fileName.endsWith('.pub')) {
			let sshKeyName = fileName.slice(0, -4);
			// if such a key exists then add it
			if (fileNames.includes(sshKeyName)) {
				sshKeyNames.add(sshKeyName);
			}
		} else {
			// or at least it should start with id_ e.g. id_dropbear
			if (fileName.startsWith('id_')) {
				let sshKeyName = fileName;
				sshKeyNames.add(sshKeyName);
			}
		}
	}
	return Array.from(sshKeyNames);
}

function _manSshConfig(opt) {
	return '<br />' + _('See %s.')
			.format('<a target="_blank" href="https://manpages.debian.org/testing/openssh-client/ssh_config.5#'+ opt + '">ssh_config ' + opt + '</a>');
}

function _discoveredKeysHint(sshKeyNames) {
	if (!sshKeyNames || sshKeyNames.length === 0)
		return '';

	return '<br />' + _('Discovered keys in %s: %s').format(
		'<code>/root/.ssh/</code>',
		sshKeyNames.map(function (name) { return '<code>' + name + '</code>'; }).join(', ')
	);
}
