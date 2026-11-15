'use strict';
'require baseclass';
'require fs';
'require rpc';
'require uci';

/*
 * Shared runtime information for the sshtunnel views.
 *
 * All data is collected through read-only ubus/file ACLs:
 *   - service.list  -> procd instances (running, pid, command)
 *   - log.read      -> recent syslog entries
 *   - /proc/net/tcp, /proc/net/tcp6 -> listening TCP ports
 *   - /proc/<pid>/stat, /proc/uptime -> process uptime
 *
 * Every RPC is wrapped in L.resolveDefault() so a missing ACL grant or an
 * older rpcd degrades to "status unavailable" instead of breaking the whole
 * configuration page.
 */

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: {}
});

const callLogRead = rpc.declare({
	object: 'log',
	method: 'read',
	params: [ 'lines', 'stream', 'oneshot' ],
	expect: { log: [] }
});

const SERVICE_NAME = 'sshtunnel-nn';

/* /proc/<pid>/stat starttime is expressed in clock ticks since boot. Linux
 * exposes USER_HZ, which is 100 on essentially every OpenWrt target. */
const CLK_TCK = 100;

function _parseListeningPorts(lines4, lines6) {
	const ports = new Set();

	for (let line of lines4.concat(lines6)) {
		const f = line.trim().split(/\s+/);
		/* sl local_address rem_address st ... ; st 0A == TCP_LISTEN */
		if (f.length < 4 || f[3] !== '0A')
			continue;

		const local = f[1].split(':');
		if (local.length < 2)
			continue;

		const port = parseInt(local[1], 16);
		if (!isNaN(port))
			ports.add(port);
	}

	return ports;
}

function _readStartTime(pid) {
	if (!pid || isNaN(parseInt(pid, 10)))
		return Promise.resolve(null);

	return L.resolveDefault(fs.read('/proc/%s/stat'.format(pid)), '').then(function (s) {
		/* comm is wrapped in parentheses and may contain spaces, so split
		 * after the last ')' and index from field 3 onwards. Field 22
		 * (starttime) therefore has index 19. */
		const i = s.lastIndexOf(')');
		if (i < 0)
			return null;

		const f = s.substring(i + 2).trim().split(/\s+/);
		const t = f.length > 19 ? parseInt(f[19], 10) : NaN;
		return isNaN(t) ? null : t;
	});
}

/* Keep our own logger output as well as the stderr of the ssh child. procd
 * forwards child stderr to syslog with a "sh[<pid>]:" tag whose pid is the
 * procd instance pid, so those diagnostics can be matched exactly instead of
 * pulling in every unrelated sshd line. */
function _filterLog(entries, pids) {
	if (!Array.isArray(entries))
		return [];

	return entries.filter(function (e) {
		if (!e || typeof e.msg !== 'string')
			return false;
		if (/sshtunnel/i.test(e.msg))
			return true;

		const m = /\bsh\[(\d+)\]:/.exec(e.msg);
		return !!(m && pids && pids.has(m[1]));
	}).map(function (e) {
		return {
			time: e.time,
			priority: e.priority,
			msg: e.msg
		};
	});
}

function _collectTunnels() {
	const out = [];
	const types = [ 'tunnelR', 'tunnelL', 'tunnelD', 'tunnelW' ];

	for (let type of types) {
		uci.sections('sshtunnel', type, function (s, sid) {
			out.push({
				type: type,
				name: sid || s['.name'] || '',
				server: s.server || '',
				enabled: (s.enabled === undefined || s.enabled === null) ? true : (s.enabled !== '0'),
				localaddress: s.localaddress || '',
				localport: s.localport || '',
				remoteaddress: s.remoteaddress || '',
				remoteport: s.remoteport || '',
				vpntype: s.vpntype || '',
				localdev: s.localdev || 'any',
				remotedev: s.remotedev || 'any'
			});
		});
	}

	return out;
}

/* Fallback used when the startup log has already scrolled out of the ring
 * buffer. The procd command is:
 *   /bin/sh -c <watch-script> sshtunnel-watch "$PROG" "$ARGS" ...
 * PROG alone is not enough because /usr/bin/ssh is often a dbclient symlink.
 * The init script passes "-nN" for OpenSSH and "-N" for Dropbear, so ARGS
 * disambiguates the two without executing anything. */
function _clientFromCommand(command) {
	if (!Array.isArray(command))
		return null;

	let prog = '', args = '';
	for (let i = 0; i < command.length - 1; i++) {
		if (command[i] === 'sshtunnel-watch') {
			prog = String(command[i + 1] || '');
			args = String(command[i + 2] || '');
			break;
		}
	}

	if (/\bdbclient\b/.test(prog))
		return 'dropbear';
	if (/\bssh\b/.test(prog)) {
		if (/(^|\s)-nN(\s|$)/.test(args)) return 'openssh';
		if (/(^|\s)-N(\s|$)/.test(args)) return 'dropbear';
	}
	return null;
}

/* The init script logs "server <name>: using <prog> (<client>)" once per
 * instance on start. Prefer that over guessing from the binary path, since
 * /usr/bin/ssh is often a symlink to dbclient. */
function _clientFromLog(logs) {
	for (let i = logs.length - 1; i >= 0; i--) {
		const m = /using\s+(\S+)\s+\((\w+)\)/.exec(logs[i].msg);
		if (m)
			return { client: m[2], prog: m[1] };
	}
	return null;
}

function _formatDuration(sec) {
	if (sec == null || !isFinite(sec) || sec < 0)
		return null;

	sec = Math.floor(sec);
	const d = Math.floor(sec / 86400);
	const h = Math.floor((sec % 86400) / 3600);
	const m = Math.floor((sec % 3600) / 60);
	const s = sec % 60;

	if (d > 0) return d + 'd ' + h + 'h';
	if (h > 0) return h + 'h ' + m + 'm';
	if (m > 0) return m + 'm ' + s + 's';
	return s + 's';
}

function _formatTime(ms) {
	if (!ms || isNaN(ms))
		return '';

	try {
		return new Date(Number(ms)).toLocaleString();
	} catch (e) {
		return '';
	}
}

const FACILITIES = [
	'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
	'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'logaudit', 'logalert',
	'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5',
	'local6', 'local7'
];

const SEVERITIES = [
	'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'
];

function _priorityText(priority) {
	if (priority == null || isNaN(priority))
		return '';

	const p = Number(priority);
	return (FACILITIES[Math.floor(p / 8)] || '?') + '.' + (SEVERITIES[p % 8] || '?');
}

function load() {
	return Promise.all([
		L.resolveDefault(callServiceList(SERVICE_NAME), {}),
		L.resolveDefault(callLogRead(200, false, true), []),
		L.resolveDefault(fs.lines('/proc/net/tcp'), []),
		L.resolveDefault(fs.lines('/proc/net/tcp6'), []),
		L.resolveDefault(fs.trimmed('/proc/uptime'), '0 0'),
		L.resolveDefault(uci.load('sshtunnel'), null)
	]).then(function (res) {
		const svc = (res[0] && res[0][SERVICE_NAME]) || {};
		const instances = (L.isObject(svc.instances)) ? svc.instances : {};
		const names = Object.keys(instances);

		const pids = new Set();
		for (let n of names) {
			const p = parseInt(instances[n].pid, 10);
			if (p > 0)
				pids.add(String(p));
		}

		const logs = _filterLog(res[1], pids);
		const ports = _parseListeningPorts(res[2], res[3]);
		const uptime = parseFloat(String(res[4] || '0').split(/\s+/)[0]) || 0;
		const tunnels = _collectTunnels();

		/* Only local/dynamic forwards bind a TCP port on this device. Counting
		 * those is more useful than reporting every system-wide listener. */
		const tunnelListening = new Set();
		for (let t of tunnels) {
			if (!t.enabled || (t.type !== 'tunnelL' && t.type !== 'tunnelD'))
				continue;
			const inst = instances[t.server];
			if (!inst || !inst.running)
				continue;
			const p = parseInt(t.localport, 10);
			if (!isNaN(p) && ports.has(p))
				tunnelListening.add(p);
		}

		return Promise.all(names.map(function (n) {
			return _readStartTime(instances[n].pid).then(function (t) {
				return [ n, t ];
			});
		})).then(function (pairs) {
			const startTimes = {};
			for (let p of pairs)
				startTimes[p[0]] = p[1];

			const detected = _clientFromLog(logs);
			let client = detected ? detected.client : null;
			let prog = detected ? detected.prog : null;

			if (!client) {
				for (let n of names)
					if (!client) client = _clientFromCommand(instances[n].command);
			}

			const durations = {};
			for (let n of names) {
				const t = startTimes[n];
				durations[n] = (t != null && uptime > 0)
					? _formatDuration(uptime - t / CLK_TCK) : null;
			}

			return {
				available: names.length > 0 || logs.length > 0,
				service: svc,
				instances: instances,
				names: names,
				logs: logs,
				ports: ports,
				tunnelListening: tunnelListening,
				tunnels: tunnels,
				client: client,
				prog: prog,
				durations: durations
			};
		});
	});
}

function _cell(value) {
	return E('td', { 'class': 'td' }, [ value == null ? '' : String(value) ]);
}

function _badge(text, ok) {
	/* Use theme variables when available (bootstrap), fall back to readable
	 * defaults for themes that do not define them (e.g. argon). The leading
	 * symbol keeps the state distinguishable even without colour support. */
	return E('span', {
		'style': 'font-weight:bold;color:var(%s, %s)'.format(
			ok ? '--success-color-high' : '--error-color-high',
			ok ? '#2e7d32' : '#c62828')
	}, [ (ok ? '\u2713 ' : '\u2717 ') + text ]);
}

/* dom.append() only iterates one array level; flatten nested child arrays
 * so conditional fragments can be composed inline. */
function _flatten(items) {
	const out = [];
	for (let item of items) {
		if (Array.isArray(item))
			out.push(..._flatten(item));
		else if (item !== null && item !== undefined && item !== '')
			out.push(item);
	}
	return out;
}

function _section(title, descr, body) {
	const nodes = [ E('h3', {}, [ title ]) ];
	if (descr)
		nodes.push(E('div', { 'class': 'cbi-section-descr' },
			Array.isArray(descr) ? _flatten(descr) : descr));
	nodes.push(body);
	return E('div', { 'class': 'cbi-section cbi-tblsection' }, nodes);
}

function _forwardSpec(t) {
	switch (t.type) {
		case 'tunnelR':
			return '-R %s:%s:%s:%s'.format(
				t.remoteaddress || '*', t.remoteport, t.localaddress, t.localport);
		case 'tunnelL':
			return '-L %s:%s:%s:%s'.format(
				t.localaddress, t.localport, t.remoteaddress, t.remoteport);
		case 'tunnelD':
			return '-D %s:%s'.format(t.localaddress, t.localport);
		case 'tunnelW':
			return '-o Tunnel=%s -w %s:%s'.format(t.vpntype, t.localdev || 'any', t.remotedev || 'any');
		default:
			return '';
	}
}

function _tunnelState(t, data) {
	if (!t.enabled)
		return { text: _('Disabled'), ok: false };

	const inst = data.instances[t.server];
	if (!inst || !inst.running)
		return { text: _('Not running'), ok: false };

	/* Only local and dynamic forwards listen on a local TCP port. Remote
	 * forwards are bound on the peer and VPN tunnels use tun/tap devices,
	 * so neither can be probed locally. */
	if (t.type === 'tunnelR')
		return { text: _('Active (remote side)'), ok: true };
	if (t.type === 'tunnelW')
		return { text: _('Active (tun/tap)'), ok: true };

	const port = parseInt(t.localport, 10);
	if (!isNaN(port) && data.ports.has(port))
		return { text: _('Listening'), ok: true };

	return { text: _('Not listening'), ok: false };
}

function _table(headers, rows) {
	const head = E('tr', { 'class': 'tr table-titles' },
		headers.map(function (h) { return E('th', { 'class': 'th' }, [ h ]); }));

	return E('table', { 'class': 'table cbi-section-table' },
		[ head ].concat(rows));
}

/* Lightweight one-line summary shared by the Servers and SSH Tunnels pages. */
function renderSummary(data) {
	if (!data.available)
		return E('div', { 'class': 'cbi-section-descr' }, [
			_('Runtime status unavailable.') + ' ',
			E('a', { 'href': L.url('admin/services/sshtunnel-nn/ssh_status') }, _('Open status page'))
		]);

	const running = data.names.filter(function (n) {
		return data.instances[n] && data.instances[n].running;
	}).length;

	const statusText = running > 0
		? _('Running (%s instance(s))').format(running)
		: _('Not running');

	const clientText = (data.client === 'dropbear')
		? 'Dropbear dbclient'
		: (data.client === 'openssh') ? 'OpenSSH' : _('Unknown');

	return E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': 'cbi-section-descr' }, [
			E('strong', {}, [ _('Service') + ': ' ]),
			_badge(statusText, running > 0),
			' \u00b7 ',
			E('strong', {}, [ _('Client') + ': ' ]), clientText,
			' \u00b7 ',
			E('strong', {}, [ _('Listening ports') + ': ' ]), String(data.tunnelListening.size),
			' \u00b7 ',
			E('strong', {}, [ _('Log entries') + ': ' ]), String(data.logs.length),
			' \u00b7 ',
			E('a', { 'href': L.url('admin/services/sshtunnel-nn/ssh_status') }, _('Open status page'))
		])
	]);
}

/* Forwarding status table, reused by the status page and the tunnels page. */
function renderForwardingTable(data) {
	const rows = data.tunnels.map(function (t) {
		const state = _tunnelState(t, data);

		return E('tr', { 'class': 'tr' }, [
			_cell(t.name),
			_cell(t.type.replace('tunnel', '')),
			_cell(t.server),
			E('td', { 'class': 'td' }, [ E('code', {}, _forwardSpec(t)) ]),
			E('td', { 'class': 'td' }, [ _badge(state.text, state.ok) ])
		]);
	});

	const body = rows.length > 0
		? _table([
			_('Name'), _('Type'), _('Server'), _('Forward'), _('State')
		], rows)
		: E('div', { 'class': 'cbi-section-descr' }, _('No tunnels configured.'));

	return _section(_('Forwarding Status'),
		_('Local and dynamic forwards are checked against the listening TCP ports on this device. Remote forwards are bound on the peer and cannot be probed locally.'),
		body);
}

/* Full diagnostics page body. */
function renderFull(data) {
	const nodes = [];

	if (!data.available) {
		nodes.push(E('div', { 'class': 'cbi-section cbi-tblsection' }, [
			E('h3', {}, [ _('Service Status') ]),
			E('div', { 'class': 'cbi-section-descr' },
				_('Runtime status unavailable. The service may be stopped or the ACL permissions may be missing.'))
		]));
	}

	/* service / instances */
	const irows = data.names.map(function (n) {
		const inst = data.instances[n] || {};
		const cmd = Array.isArray(inst.command) ? inst.command.join(' ') : String(inst.command || '');

		return E('tr', { 'class': 'tr' }, [
			_cell(n),
			E('td', { 'class': 'td' }, [
				_badge(inst.running ? _('Running') : _('Stopped'), !!inst.running)
			]),
			_cell(inst.pid || ''),
			_cell(data.durations[n] || ''),
			E('td', { 'class': 'td' }, [ E('code', { 'style': 'word-break:break-all' }, cmd) ])
		]);
	});

	const clientText = (data.client === 'dropbear') ? 'Dropbear dbclient'
		: (data.client === 'openssh') ? 'OpenSSH' : _('Unknown');

	const itable = irows.length > 0
		? _table([
			_('Server'), _('State'), _('PID'), _('Uptime'), _('Command Line')
		], irows)
		: E('div', { 'class': 'cbi-section-descr' }, _('No running instances.'));

	nodes.push(_section(_('Service Status'), [
		E('strong', {}, [ _('Service') + ': ' ]), SERVICE_NAME, ' \u00b7 ',
		E('strong', {}, [ _('Client') + ': ' ]), clientText,
		data.prog ? [ ' \u00b7 ', E('strong', {}, [ _('Program') + ': ' ]), data.prog ] : ''
	], itable));

	nodes.push(renderForwardingTable(data));

	/* recent log */
	const lrows = data.logs.slice(-60).reverse().map(function (e) {
		return E('tr', { 'class': 'tr' }, [
			_cell(_formatTime(e.time)),
			_cell(_priorityText(e.priority)),
			E('td', { 'class': 'td' }, [
				E('code', { 'style': 'word-break:break-all' }, e.msg)
			])
		]);
	});

	const ltable = lrows.length > 0
		? _table([ _('Time'), _('Priority'), _('Message') ], lrows)
		: E('div', { 'class': 'cbi-section-descr' }, _('No log entries found.'));

	nodes.push(_section(_('Recent Log'),
		_('Most recent sshtunnel syslog entries (newest first).'), ltable));

	nodes.push(E('div', { 'class': 'cbi-page-actions' }, [
		E('button', {
			'class': 'btn cbi-button cbi-button-apply',
			'click': function () { location.reload(); }
		}, [ _('Refresh') ])
	]));

	return E('div', {}, nodes);
}

/* LuCI's require() expects every module factory to yield a baseclass
 * subclass; it instantiates the class and injects that instance into the
 * views which require it. Returning a plain object would fail the
 * Class.isSubclass() check with "factory yields invalid constructor". */
return baseclass.extend({
	load: load,
	renderSummary: renderSummary,
	renderForwardingTable: renderForwardingTable,
	renderFull: renderFull
});
