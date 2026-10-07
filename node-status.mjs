// Status reports recent authenticated observations, not a proof of operator
// independence or of the current liveness of a remote process.
export function networkStatus(cfg, peers, admitted, now = Date.now()) {
  if (!Array.isArray(peers) || peers.length > 64 || !Array.isArray(admitted)) throw new Error('Invalid network status input');
  const observations = peers.map(peer => {
    const pin = admitted.find(value => value.id === peer.id);
    const fresh = peer.confirmed === true && Number.isSafeInteger(peer.lastSeen) && now >= peer.lastSeen && now - peer.lastSeen < 30000;
    const admittedWitness = Boolean(pin && (!pin.notaryPublicKey || pin.notaryPublicKey === peer.notaryPublicKey));
    return {
      id: peer.id, address: peer.address, outboundOnly: peer.outboundOnly === true,
      recentlyAuthenticated: fresh, mesh: fresh && peer.mesh === true,
      reachable: fresh && Boolean(peer.mesh || peer.relayVia || peer.dialable),
      admittedWitness, witnessReady: fresh && admittedWitness && peer.notaryReady !== false && Boolean(peer.dialable || peer.mesh || peer.relayVia),
      lastSeenAgeMs: Number.isSafeInteger(peer.lastSeen) ? Math.max(0, now - peer.lastSeen) : null,
      ...(peer.relayVia ? { relayVia: peer.relayVia } : {}),
    };
  });
  return {
    nodeId: cfg.id, discovery: cfg.discovery || 'closed', outboundOnly: cfg.outboundOnly === true,
    bootstraps: cfg.bootstraps || [], observedPeers: observations.length,
    connectedPeers: observations.filter(peer => peer.mesh).length,
    reachablePeers: observations.filter(peer => peer.reachable).length,
    relayReachablePeers: observations.filter(peer => peer.recentlyAuthenticated && peer.relayVia).length,
    readyWitnesses: observations.filter(peer => peer.witnessReady).length,
    peers: observations,
  };
}
