import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
let pendingLookups = 0;

function parseAddress(value) {
  if (typeof value !== 'string' || value.length > 300 || /\s|[\\/@?#%]/.test(value)) throw new Error('Invalid discovery address');
  const parsed = new URL('tls://' + value);
  if (!parsed.hostname || !parsed.port || parsed.username || parsed.password || parsed.pathname || parsed.search || parsed.hash) throw new Error('Discovery address must be host:port');
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1025 || port > 65535) throw new Error('Invalid discovery port');
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!isIP(host) && (!/^(?=.{1,253}\.?$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?$/i.test(host) || host.replace(/\.$/, '').split('.').some(label => !label.length || label.length > 63 || label.startsWith('-') || label.endsWith('-')))) throw new Error('Invalid discovery hostname');
  return { host, port };
}
function ipv4Number(ip) {
  const parts = ip.split('.').map(Number);
  return parts.reduce((n, part) => (n << 8n) | BigInt(part), 0n);
}
function ipv6Number(ip) {
  let input = ip.toLowerCase();
  if (input.includes('.')) {
    const split = input.lastIndexOf(':'); const n = ipv4Number(input.slice(split + 1));
    input = input.slice(0, split + 1) + (n >> 16n).toString(16) + ':' + (n & 65535n).toString(16);
  }
  const parts = input.split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const words = parts.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return words.reduce((n, word) => (n << 16n) | BigInt('0x' + word), 0n);
}
function inPrefix(value, base, bits, width) { const shift = BigInt(width - bits); return value >> shift === base >> shift; }
const V4_DENIED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => [ipv4Number(base), bits]);
const V6_DENIED = [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]].map(([base, bits]) => [ipv6Number(base), bits]);
function classify(ip) {
  if (typeof ip !== 'string' || ip.includes('%')) return { family: 0, number: 0n };
  const family = isIP(ip);
  if (family === 4) return { family, number: ipv4Number(ip) };
  if (family === 6) {
    const number = ipv6Number(ip);
    // IPv4-mapped addresses must follow the embedded IPv4 policy.
    if (number >> 32n === 65535n) return { family: 4, number: number & 0xffffffffn };
    return { family, number };
  }
  return { family: 0, number: 0n };
}
export function isDiscoveryAddressAllowed(ip, mode = 'public') {
  if (mode !== 'public' && mode !== 'local-test') return false;
  const { family, number } = classify(ip);
  if (mode === 'local-test') return family === 4 ? inPrefix(number, ipv4Number('127.0.0.0'), 8, 32) : family === 6 && number === 1n;
  if (family === 4) return !V4_DENIED.some(([base, bits]) => inPrefix(number, base, bits, 32));
  if (family === 6) return inPrefix(number, ipv6Number('2000::'), 3, 128) && !V6_DENIED.some(([base, bits]) => inPrefix(number, base, bits, 128));
  return false;
}
export function checkedDiscoveryRecords(records) {
  if (!Array.isArray(records) || !records.length || records.length > 16 || records.some(record => !record || !isDiscoveryAddressAllowed(record.address, 'public'))) throw new Error('Discovery hostname resolves to a disallowed address');
  return records[0].address;
}

// Discovery never dials a hostname after checking DNS; return a checked numeric address.
export async function discoveryTarget(address, mode = 'public') {
  if (mode !== 'public' && mode !== 'local-test') throw new Error('Unknown discovery mode');
  const { host, port } = parseAddress(address);
  if (isIP(host)) {
    if (!isDiscoveryAddressAllowed(host, mode)) throw new Error('Discovery target is not permitted');
    return { host, port };
  }
  if (mode === 'local-test') throw new Error('Local-test discovery requires numeric loopback address');
  if (pendingLookups >= 8) throw new Error('Discovery DNS concurrency limit');
  pendingLookups++;
  let lookupPromise;
  try { lookupPromise = lookup(host, { all: true, verbatim: true }); }
  catch (error) { pendingLookups--; throw error; }
  // DNS cannot be cancelled: retain capacity until the underlying request settles,
  // even when the application deadline has already expired.
  const boundedLookup = lookupPromise.then(
    records => { pendingLookups--; return records; },
    error => { pendingLookups--; throw error; },
  );
  let timeout;
  try {
    const records = await Promise.race([
      boundedLookup,
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Discovery DNS timeout')), 3000); }),
    ]);
    return { host: checkedDiscoveryRecords(records), port, servername: host };
  } finally { clearTimeout(timeout); }
}
