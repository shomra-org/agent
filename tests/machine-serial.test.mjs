import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanSerial, parseIoregSerial, readMachineSerial } from '../src/core/machine-serial.mjs';
import { getMachineSerial } from '../src/core/config.mjs';

test('placeholder serials a whole fleet shares are refused', () => {
  for (const v of ['To be filled by O.E.M.', 'Default string', '0', '000000', 'System Serial Number', '', null, 'N/A']) {
    assert.equal(cleanSerial(v), null, String(v));
  }
  assert.equal(cleanSerial('  C02XYZ123\n'), 'C02XYZ123');
});

test('ioreg output yields the platform serial', () => {
  assert.equal(parseIoregSerial('| "IOPlatformSerialNumber" = "C02DK1ABMD6T"'), 'C02DK1ABMD6T');
  assert.equal(parseIoregSerial('no serial here'), null);
});

test('an unknown platform reads nothing rather than guessing', () => {
  assert.equal(readMachineSerial('aix'), null);
});

test('a cached serial is reused and a failed read is not cached', () => {
  const cfg = { serial: 'CACHED1' };
  assert.equal(getMachineSerial(cfg, () => 'OTHER'), 'CACHED1');
  const empty = {};
  assert.equal(getMachineSerial(empty, () => null), null);
  assert.equal(empty.serial, undefined);
});

test('a user run inherits the machine-wide id so one machine is one endpoint', async () => {
  const { inheritedMachineId } = await import('../src/core/config.mjs');
  assert.equal(inheritedMachineId({}, { machineId: 'wide' }), 'wide');
  assert.equal(inheritedMachineId({ machineId: 'own' }, { machineId: 'wide' }), null);
  assert.equal(inheritedMachineId({}, null), null);
  assert.equal(inheritedMachineId({}, { machineId: '' }), null);
});
