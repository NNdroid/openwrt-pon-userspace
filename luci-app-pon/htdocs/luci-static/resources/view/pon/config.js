// SPDX-License-Identifier: Apache-2.0

'use strict';
'require fs';
'require form';
'require ui';
'require uci';
'require view';

/* Printable ASCII keeps JavaScript character counts equal to wire byte counts. */
function validatePrintableAscii(value, minimum, maximum) {
	if (value == null || value === '')
		return true;

	if (!/^[\x20-\x7e]+$/.test(value))
		return _('Only printable ASCII characters are allowed.');

	if (value.length < minimum || value.length > maximum) {
		if (minimum === maximum)
			return _('The value must contain exactly %d bytes.').format(maximum);

		return _('The value must contain between %d and %d bytes.')
			.format(minimum, maximum);
	}

	return true;
}

function asciiLength(minimum, maximum) {
	return function(sectionId, value) {
		return validatePrintableAscii(value, minimum, maximum);
	};
}

function validateSerialNumber(sectionId, value) {
	if (value == null || value === '')
		return true;

	if (/^[0-9a-fA-F]{16}$/.test(value) ||
	    /^[A-Za-z0-9]{4}[0-9a-fA-F]{8}$/.test(value))
		return true;

	return _('Use 16 hexadecimal digits or VEND followed by 8 hexadecimal digits.');
}

function validateMacAddress(sectionId, value) {
	var first;

	if (value == null || value === '')
		return true;

	if (!/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(value))
		return _('Use six colon-separated hexadecimal bytes, e.g. 00:11:22:33:44:55.');

	first = parseInt(value.slice(0, 2), 16);
	if (first & 1)
		return _('The PON MAC address must be a unicast address.');
	if (/^00:00:00:00:00:00$/i.test(value))
		return _('The PON MAC address must not be all zeros.');

	return true;
}

function validateChipsetId(sectionId, value) {
	if (value == null || value === '' || /^[0-9a-fA-F]{16}$/.test(value))
		return true;

	return _('Use 16 hexadecimal digits.');
}

function isEponMode(mode) {
	return (mode || '').indexOf('epon-') === 0;
}

function sectionUsesEpon(sectionId) {
	var line = uci.get('pon', sectionId, 'line');

	return isEponMode(uci.get('pon', line, 'mode'));
}

function formatStorageSize(bytes) {
	var units = [ 'B', 'KiB', 'MiB', 'GiB' ];
	var size = Number(bytes);
	var unit = 0;

	while (size >= 1024 && unit < units.length - 1) {
		size /= 1024;
		unit++;
	}

	return '%s %s'.format(size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1), units[unit]);
}

function parseStorageList(output) {
	var targets = JSON.parse(output);
	return Object.keys(targets).map(function(name) {
		var target = targets[name];
		return {
			id: name,
			label: '%s · %s · %s'.format(
				name, target.type.toUpperCase(), formatStorageSize(target.size))
		};
	});
}

function printableWire(hex) {
	return (String(hex || '').match(/../g) || []).map(function(pair) {
		var code = parseInt(pair, 16);
		return (code >= 0x20 && code <= 0x7e) ? String.fromCharCode(code) : '';
	}).join('');
}

function spacedWire(hex) {
	return (String(hex || '').match(/../g) || []).join(' ');
}

function applyActualValue(o, field, note) {
	if (!field) {
		o.description = _('The running OAM agent does not report the current value.');
		return;
	}

	if (field.text)
		o.placeholder = _('Currently: %s').format(field.text);

	o.description = field.sent ?
		_('Actually sent: %s').format(spacedWire(field.wire)) :
		_('Not sent with the current OAM profile or CTC version.');

	if (note)
		o.description += ' ' + note;
}

return view.extend({
	load: function() {
		return Promise.all([
			fs.exec('/usr/libexec/airoha-pon-data', [ 'list' ]).then(function(result) {
				if (result.code != 0)
					throw new Error(result.stderr || result.stdout || _('Unable to list storage.'));

				return parseStorageList(result.stdout);
			}),
			uci.load('pon').then(function() {
				var sections = uci.sections('pon', 'oam');

				if (!sections.length || !sections[0].line)
					return null;
				return L.resolveDefault(fs.exec_direct('/usr/bin/pondctl',
					[ 'status', '--line', sections[0].line ]), null);
			}).catch(function() {
				return null;
			}).then(function(output) {
				if (!output)
					return null;
				try {
					return JSON.parse(output);
				} catch (error) {
					return null;
				}
			})
		]).then(function(results) {
			return { storages: results[0], oam: results[1] };
		});
	},

	handleBoardDataUpload: function(storages, selector) {
		var storage = storages[Number(selector.value)];

		return ui.uploadFile('/tmp/pon-board-data.bin').then(function() {
			return fs.exec('/usr/libexec/airoha-pon-data', [ 'write', storage.id ]).then(function(result) {
				if (result.code != 0)
					throw new Error(result.stderr || result.stdout || _('Write failed.'));

				var message = [
					_('Board data written to %s and verified. Reboot the device to apply it.')
						.format(storage.label)
				];
				if (result.stdout.trim())
					message.push(E('br'), result.stdout.trim());
				ui.addNotification(null, E('p', message));
			}).catch(function(error) {
				ui.addNotification(null, E('p', [
					_('Writing board data failed: %s').format(error.message)
				]));
			});
		});
	},

	render: function(data) {
		var m, s, o, selector, storages, oam, identity;

		storages = data.storages;
		oam = data.oam;
		identity = oam ? oam.onu_identity : null;

		m = new form.Map('pon', _('PON'),
			_('Project source:') +
			' <a href="https://github.com/pbs05/openwrt-pon-userspace/tree/main/luci-app-pon" target="_blank" rel="noreferrer noopener">openwrt-pon-userspace/luci-app-pon</a>');
		m.readonly = !L.hasViewPermission();

		s = m.section(form.TypedSection, 'xpon', _('PON line'));
		s.anonymous = false;
		s.addremove = false;
		s.description = _('Line mode and registration identity take effect after the PON interface restarts.');

		o = s.option(form.DummyValue, 'device', _('PON interface'));
		o.default = '-';

		o = s.option(form.ListValue, 'mode', _('Line mode'));
		o.default = '';
		o.value('', _('Driver default'));
		o.value('xgpon', _('XG-PON'));
		o.value('xgspon', _('XGS-PON'));
		o.value('epon-10g-1g', _('10G-EPON 10G/1G'));
		o.value('epon-10g-10g', _('10G-EPON 10G/10G'));

		o = s.option(form.Value, 'serial_number', _('Serial number (SN)'));
		o.placeholder = _('Board serial number');
		o.rmempty = true;
		o.validate = validateSerialNumber;
		o.depends('mode', '');
		o.depends('mode', 'xgpon');
		o.depends('mode', 'xgspon');
		o.description = _('Used only by XG-PON and XGS-PON PLOAM registration; EPON registers with the PON MAC address.');

		o = s.option(form.Value, 'registration_id', _('Registration-ID'));
		o.password = true;
		o.rmempty = true;
		o.depends('mode', '');
		o.depends('mode', 'xgpon');
		o.depends('mode', 'xgspon');
		o.validate = asciiLength(1, 36);
		o.description = _('Optional; sent as all zeros when empty.');

		o = s.option(form.Value, 'macaddr', _('PON MAC address'));
		o.placeholder = _('Board MAC address');
		o.rmempty = true;
		o.validate = validateMacAddress;
		o.description = _('Overrides the PON interface MAC used for EPON registration and the CTC ONU SN. Takes effect after a PON restart. Clearing it restores the factory MAC only after a reboot.');

		s = m.section(form.TypedSection, 'omci', _('OMCI settings'));
		s.anonymous = false;
		s.addremove = false;
		s.filter = function(sectionId) {
			return !sectionUsesEpon(sectionId);
		};
		s.tab('authentication', _('Authentication'));
		s.tab('identity', _('ONU identity'));
		s.tab('compatibility', _('Compatibility'));

		o = s.taboption('authentication', form.DummyValue, 'line', _('XG-PON configuration'));
		o.default = '-';

		o = s.taboption('authentication', form.DummyValue, 'device', _('OMCI interface'));
		o.default = '-';

		o = s.taboption('authentication', form.Value, 'loid', _('LOID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 24);

		o = s.taboption('authentication', form.ListValue, 'loid_padding', _('LOID padding'));
		o.default = 'trailing';
		o.value('leading', _('Before the LOID (right aligned)'));
		o.value('trailing', _('After the LOID (left aligned)'));
		o.description = _('Which side of the 24-byte LOID field carries the 0x00 fill.');

		o = s.taboption('authentication', form.Value, 'loid_password', _('LOID password'));
		o.password = true;
		o.rmempty = true;
		o.validate = asciiLength(1, 12);

		o = s.taboption('identity', form.Value, 'vendor_id', _('Vendor ID'));
		o.rmempty = true;
		o.validate = asciiLength(4, 4);
		o.description = _('Usually the same as the first four characters of the serial number.');

		o = s.taboption('identity', form.Value, 'equipment_id', _('Equipment ID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 20);

		o = s.taboption('identity', form.Value, 'hardware_version', _('Hardware version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 14);

		o = s.taboption('identity', form.Value, 'software_version', _('Software version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 14);

		o = s.taboption('identity', form.Value, 'operator_id', _('Operator ID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 4);

		o = s.taboption('compatibility', form.ListValue, 'omcc_version', _('OMCC version'));
		o.value('0xb0', '0xb0');
		o.value('0x86', '0x86');
		o.default = '0xb0';
		o.rmempty = false;
		o.description = _('If the ONU cannot register with a Huawei OLT, try OMCC version 0x86.');

		o = s.taboption('compatibility', form.Flag, 'disable_enhanced_security', _('Disable enhanced security (Class 332)'));
		o.default = '0';
		o.rmempty = true;

		o = s.taboption('compatibility', form.Value, 'alloc_id_timeout', _('Alloc-ID wait timeout'));
		o.datatype = 'uinteger';
		o.placeholder = '30';
		o.rmempty = true;
		o.description = _('Seconds a data path may wait for PLOAM to assign its Alloc-ID before it is reported as failed. The ONU keeps waiting afterwards; 0 disables the timeout.');

		s = m.section(form.TypedSection, 'oam', _('EPON OAM settings'));
		s.anonymous = false;
		s.addremove = false;
		s.filter = function(sectionId) {
			return sectionUsesEpon(sectionId);
		};
		s.tab('authentication', _('Authentication'));
		s.tab('identity', _('ONU identity'));

		o = s.taboption('authentication', form.DummyValue, 'line', _('EPON configuration'));
		o.default = '-';

		o = s.taboption('authentication', form.DummyValue, 'device', _('OAM interface'));
		o.default = '-';

		o = s.taboption('authentication', form.ListValue, 'operator', _('OAM profile'));
		o.default = 'ctc';
		o.value('ieee', _('IEEE 802.3ah'));
		o.value('ctc', _('IEEE 802.3ah + CTC'));

		o = s.taboption('authentication', form.Value, 'loid', _('LOID'));
		o.rmempty = true;
		o.depends('operator', 'ctc');
		o.validate = asciiLength(1, 24);
		applyActualValue(o, oam && typeof oam.loid_sent === 'string' ? {
			text: printableWire(oam.loid_sent) || _('Not configured'),
			wire: oam.loid_sent,
			sent: oam.operator === 'ctc'
		} : null);

		o = s.taboption('authentication', form.ListValue, 'loid_padding', _('LOID padding'));
		o.default = 'leading';
		o.depends('operator', 'ctc');
		o.value('leading', _('Before the LOID (right aligned)'));
		o.value('trailing', _('After the LOID (left aligned)'));
		o.description = _('Which side of the 24-byte LOID field carries the 0x00 fill.');

		o = s.taboption('authentication', form.Value, 'loid_password', _('LOID password'));
		o.password = true;
		o.rmempty = true;
		o.depends('operator', 'ctc');
		o.validate = asciiLength(1, 12);

		o = s.taboption('identity', form.Value, 'vendor_id', _('Vendor ID'));
		o.rmempty = true;
		o.validate = asciiLength(4, 4);
		applyActualValue(o, identity && identity.vendor_id);

		o = s.taboption('identity', form.Value, 'model', _('ONU short model'));
		o.rmempty = true;
		o.validate = asciiLength(4, 4);
		applyActualValue(o, identity && identity.model);

		o = s.taboption('identity', form.Value, 'equipment_id', _('Equipment ID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 16);
		applyActualValue(o, identity && identity.equipment_id);

		o = s.taboption('identity', form.Value, 'hardware_version', _('Hardware version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 8);
		applyActualValue(o, identity && identity.hardware_version);

		o = s.taboption('identity', form.Value, 'software_version', _('Software version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 16);
		applyActualValue(o, identity && identity.software_version);

		o = s.taboption('identity', form.Value, 'firmware_version', _('Firmware version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 127);
		applyActualValue(o, identity && identity.firmware_version);

		o = s.taboption('identity', form.Value, 'chipset_id', _('Chipset ID'));
		o.rmempty = true;
		o.validate = validateChipsetId;
		applyActualValue(o, identity && identity.chipset_id);

		o = s.taboption('identity', form.Value, 'ge_ports', _('Ethernet port count'));
		o.default = '1';
		o.datatype = 'range(1,64)';
		applyActualValue(o, identity && identity.ge_ports,
			_('The port count is embedded in the 26-byte ONU capabilities attribute.'));

		return m.render().then(L.bind(function(map) {
			if (!storages.length)
				return map;

			selector = E('select', { 'class': 'cbi-input-select' },
				storages.map(function(storage, index) {
					return E('option', { 'value': String(index) }, storage.label);
				}));

			return E([], [ map,
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, _('PON board data')),
					E('div', { 'class': 'cbi-value' }, [
						E('label', { 'class': 'cbi-value-title' }, _('Target storage')),
						E('div', { 'class': 'cbi-value-field' }, [
							selector,
							E('button', {
								'class': 'cbi-button cbi-button-action',
								'disabled': m.readonly || null,
								'click': ui.createHandlerFn(this, 'handleBoardDataUpload', storages, selector)
							}, [ _('Upload and write') ])
						])
					])
				])
			]);
		}, this));
	}
});
