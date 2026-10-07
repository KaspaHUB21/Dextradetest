# Peer transport and discovery

Every installation has its own persistent Ed25519 identity. Peer IDs are SHA-256
hashes of the identity public key. TLS certificate public keys must match that
ID; descriptor signatures bind the advertised address and notary public key.
An authenticated identity does not demonstrate an independent or honest operator.

Public installations use the shipped bootstrap identity and address as their
first discovery contact. Bootstrap peers return signed peer descriptors. A node
checks address restrictions, authenticates the remote certificate, and builds
mutually authenticated TLS 1.3 mesh links. Invalid DNS/private destinations and
changes to pinned addresses fail closed. Approved witness admission is a separate
policy: discovery never creates permission to attest results.

## Outbound-only installations

An outbound-only node advertises no public address. It establishes outbound mesh
links to reachable peers. A reachable peer can advertise these currently linked
nodes as relayed discovery targets. Two outbound-only nodes can then exchange
requests through that peer without opening inbound firewall ports.

The relay routes only to an existing authenticated mesh ID. It cannot request an
arbitrary IP address, port, or URL. Each tunneled connection establishes another
mutual TLS 1.3 session **between the original nodes**. Both ends verify the actual
peer certificate and signed descriptor. The relay forwards ciphertext and cannot
replace either endpoint's identity or grant job/witness permissions. It can drop
traffic, observe volume/timing, or become unavailable.

The prototype bounds relay use to eight concurrent tunnels globally, four per
origin identity, thirty new tunnels per minute per identity and sixty globally,
a 310-second tunnel
lifetime, and existing mesh stream byte/window limits. These limits bound local
resources; they do not prevent coordinated identities from consuming capacity.

Relay discovery is currently one hop. Nodes may use multiple reachable peers,
and relay candidates rotate rather than permanently selecting the first eight.
Relayed routes disappear when the providing mesh link closes. An outbound-only
node still depends on at least one available reachable relay; two completely
disconnected outbound-only installations cannot discover one another.

## Bootstrap outages and scaling

Nodes retain a bounded cache of signed dialable descriptors across restarts.
Cached records begin unconfirmed and are reauthenticated before being reported
online. Existing direct mesh connections keep working if a bootstrap disappears;
a restarted node can reconnect to cached reachable peers. Brand-new installations
still need a live known entry point. Additional bootstrap peers can be configured
to remove dependence on the single shipped entry point.

Peer lists, concurrent transports, streams and discovery work are bounded. This
is a bounded prototype rather than an implementation of a global unbounded DHT.
Large-network resilience, routing diversity, NAT traversal without relay, relay
incentives, and protection against Sybil/eclipse attacks need further design and
load testing. Public discovery is decentralized transport, not proof of
decentralized witness independence.

## Tests

`tests/discovery-network.mjs` exercises three directly reachable nodes and two
outbound-only nodes: transitive discovery, end-to-end relayed identity checks,
absence of automatic witness trust, denied non-mesh relay requests, pinned-address
redirection, private-address rejection, explicit caller revocation, and restart
reconnection while the bootstrap is offline. `tests/relay-jobs.mjs` additionally
uses one reachable relay and three outbound nodes: a requester sends a job to a
worker, which notarizes a real API response through a separate outbound witness.
It verifies the retrieved full proof, duplicate acceptance rejection, and
verification after every process stops. Local tests do not establish
independence of operators or behavior under arbitrary Internet conditions.
