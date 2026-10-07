// Discovery pin only: this identity receives no permission to run or witness jobs.
export const DEFAULT_BOOTSTRAP = Object.freeze({
  address: 'kasvio.network:9443',
  // The existing anchor signs this numeric advertised address. This explicit
  // alias avoids accepting arbitrary redirects from gossip or DNS.
  descriptorAddress: '152.53.92.135:9443',
  id: 'bc1886af011f62966d09dce0441216b83078e55258fd68e5f83510ba0e516188',
});
export function initialBootstraps(discovery, nodeId) {
  return discovery === 'public' && nodeId !== DEFAULT_BOOTSTRAP.id ? [{ ...DEFAULT_BOOTSTRAP }] : [];
}
export function pinAcceptsAddress(pin, value) {
  return pin.address === value || pin.descriptorAddress === value;
}
