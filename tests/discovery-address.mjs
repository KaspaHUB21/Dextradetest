import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import { syncBuiltinESMExports } from 'node:module';
import { discoveryTarget, isDiscoveryAddressAllowed, checkedDiscoveryRecords } from '../discovery-address.mjs';
const denied = [
  '0.0.0.0', '0.12.1.2', '10.0.0.1', '100.64.0.1', '100.127.255.255', '127.0.0.1', '127.42.0.2',
  '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.0.0.9', '192.0.2.1', '192.88.99.1',
  '192.168.1.1', '198.18.0.1', '198.19.255.255', '198.51.100.1', '203.0.113.1', '224.0.0.1', '239.255.255.255',
  '240.0.0.1', '255.255.255.255', '::', '::1', '::127.0.0.1', '::ffff:127.0.0.1', '::ffff:7f00:1',
  '::ffff:10.0.0.1', '::ffff:192.0.2.1', 'fc00::1', 'fd00::1', 'fe80::1', 'ff02::1', '64:ff9b::a00:1',
  '2001::1', '2001:2::1', '2001:10::1', '2001:20::1', '2001:db8::1', '2002:7f00:1::1', '3fff::1',
  '3fff:fff:ffff::1', '4000::1', '5f00::1', 'fe80::1%eth0', 'not-an-ip',
];
for (const ip of denied) assert.equal(isDiscoveryAddressAllowed(ip), false, ip);
const allowed = ['1.1.1.1', '8.8.8.8', '100.63.255.255', '100.128.0.1', '172.15.255.255', '172.32.0.1', '192.31.196.1', '198.17.255.255', '198.20.0.1', '223.255.255.255', '2606:4700:4700::1111', '2001:4860:4860::8888', '2001:200::1', '::ffff:8.8.8.8', '::ffff:808:808'];
for (const ip of allowed) assert.equal(isDiscoveryAddressAllowed(ip), true, ip);
assert.equal(checkedDiscoveryRecords([{ address: '8.8.8.8' }, { address: '2606:4700:4700::1111' }]), '8.8.8.8');
for (const records of [[], null, [{ address: '8.8.8.8' }, { address: '127.0.0.1' }], [{ address: '8.8.8.8' }, { address: '::ffff:10.0.0.1' }], Array(17).fill({ address: '8.8.8.8' }), [null], [{ address: 'invalid' }]]) assert.throws(() => checkedDiscoveryRecords(records));
for (const ip of ['127.0.0.1', '127.42.0.2', '::1', '::ffff:127.0.0.1']) assert.equal(isDiscoveryAddressAllowed(ip, 'local-test'), true, ip);
for (const ip of ['10.0.0.1', '192.168.0.1', '8.8.8.8', 'fe80::1', 'fc00::1']) assert.equal(isDiscoveryAddressAllowed(ip, 'local-test'), false, ip);
assert.deepEqual(await discoveryTarget('8.8.8.8:9443'), { host: '8.8.8.8', port: 9443 });
assert.deepEqual(await discoveryTarget('[2606:4700:4700::1111]:9443'), { host: '2606:4700:4700::1111', port: 9443 });
assert.deepEqual(await discoveryTarget('[::1]:9443', 'local-test'), { host: '::1', port: 9443 });
assert.deepEqual(await discoveryTarget('127.0.0.2:9443', 'local-test'), { host: '127.0.0.2', port: 9443 });
for (const value of ['127.0.0.1:9443', '10.0.0.1:9443', '[::ffff:127.0.0.1]:9443', '8.8.8.8:443', '8.8.8.8:65536', 'user@8.8.8.8:9443', '8.8.8.8:9443/path', '8.8.8.8:9443#x', '8.8.8.8:9443?x', '[fe80::1%eth0]:9443', 'a..b:9443', 'bad_name:9443', 'a-.example:9443', '8.8.8.8:9443\\x']) await assert.rejects(discoveryTarget(value), undefined, value);
await assert.rejects(discoveryTarget('localhost:9443', 'local-test'));
await assert.rejects(discoveryTarget('8.8.8.8:9443', 'local-test'));
await assert.rejects(discoveryTarget('8.8.8.8:9443', 'unknown'));
// localhost resolution uses the machine's local host database, not external DNS.
await assert.rejects(discoveryTarget('localhost:9443'), /disallowed/);
// Mock only the builtin resolver: no external network and no injectable production bypass.
const actualLookup = dnsPromises.lookup;
const pending = [];
try {
  dnsPromises.lookup = () => new Promise((resolve, reject) => pending.push({ resolve, reject }));
  syncBuiltinESMExports();
  const held = Array.from({ length: 8 }, (_, index) => discoveryTarget('peer' + index + '.example:9443'));
  const heldResults = Promise.allSettled(held);
  await assert.rejects(discoveryTarget('overflow.example:9443'), /concurrency/);
  assert.equal(pending.length, 8);
  const results = await heldResults;
  assert.ok(results.every(result => result.status === 'rejected' && /timeout/.test(result.reason.message)));
  // Application timeout does not release a still-running OS lookup's slot.
  await assert.rejects(discoveryTarget('still-full.example:9443'), /concurrency/);
  pending[0].reject(new Error('Mock resolver failure'));
  await Promise.resolve(); await Promise.resolve();
  const next = discoveryTarget('recovered.example:9443');
  assert.equal(pending.length, 9);
  pending[8].resolve([{ address: '8.8.8.8' }]);
  assert.deepEqual(await next, { host: '8.8.8.8', port: 9443, servername: 'recovered.example' });
} finally {
  for (const request of pending) request.resolve([{ address: '8.8.8.8' }]);
  await Promise.resolve(); await Promise.resolve();
  dnsPromises.lookup = actualLookup; syncBuiltinESMExports();
}
console.log(JSON.stringify({ passed: true, deniedAddresses: denied.length, allowedAddresses: allowed.length, parserAndModeChecks: true, dnsRecordAndConcurrencyChecks: true }));
