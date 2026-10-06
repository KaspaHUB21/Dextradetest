import { Duplex } from 'node:stream';
import { randomBytes } from 'node:crypto';

const FRAME = 64 * 1024;
const WINDOW = 256 * 1024;
const QUEUE = 1024 * 1024;
const STREAM_BYTES = 128 * 1024 * 1024;
const OPEN = 1, DATA = 2, END = 3, RESET = 4, CREDIT = 5, PING = 6, PONG = 7;

// The caller must authenticate the underlying socket before creating a link.
export function createMeshLink(socket, { initiator, onStream, onClose } = {}) {
  if (typeof initiator !== 'boolean' || typeof onStream !== 'function') throw new Error('Mesh link requires role and stream handler');
  if (socket.destroyed || socket.readableEnded) throw new Error('Mesh transport already closed');
  let closed = false; let nextLocal = initiator ? 1 : 2; let lastRemote = initiator ? 0 : -1;
  const localParity = initiator ? 1 : 0;
  const streams = new Map(); const retiredStreams = new Map(); const queue = [];
  let queueBytes = 0; let blocked = false; let receiving = Buffer.alloc(0);
  let lastPong = Date.now(); let pendingPing;
  let sentBytes = 0; let receivedBytes = 0;
  function retire(id, state) {
    retiredStreams.set(id, state);
    if (retiredStreams.size > 128) retiredStreams.delete(retiredStreams.keys().next().value);
  }
  function queuedBytes() { return queueBytes + (socket.writableLength || 0); }
  function canSend(length) { return !closed && queuedBytes() + 9 + length <= QUEUE; }
  function drainQueue() {
    if (closed || blocked) return;
    while (queue.length && !blocked) {
      const frame = queue.shift(); queueBytes -= frame.length;
      blocked = !socket.write(frame);
    }
  }
  function send(type, id, body = Buffer.alloc(0)) {
    if (!canSend(body.length)) return false;
    const frame = Buffer.allocUnsafe(9 + body.length);
    frame.writeUInt32BE(body.length, 0); frame.writeUInt32BE(id, 4); frame[8] = type; body.copy(frame, 9);
    queue.push(frame); queueBytes += frame.length; drainQueue(); return true;
  }
  function control(type, id, body) {
    if (!send(type, id, body)) fail(new Error('Mesh socket queue limit'));
  }
  function flushWrites() {
    if (closed) return;
    // Round-robin scheduling limits one stream to one frame per turn.
    let progress;
    do { progress = false; for (const stream of streams.values()) if (stream.flushFrame()) progress = true; }
    while (progress && !closed && canSend(FRAME));
  }
  class MeshStream extends Duplex {
    constructor(id) {
      super({ allowHalfOpen: true, readableHighWaterMark: FRAME, writableHighWaterMark: FRAME });
      this.id = id; this.socket = socket;
      this.remoteAddress = socket.remoteAddress;
      this.sendCredit = WINDOW; this.receiveCredit = WINDOW; this.bytes = 0;
      this.localEnded = false; this.remoteEnded = false; this.remoteReset = false;
      this.pendingWrite = undefined; this.idleMilliseconds = 120000;
      this.on('error', () => {});
      this.lifetime = setTimeout(() => this.destroy(new Error('Mesh stream lifetime exceeded')), 310000);
      this.lifetime.unref?.(); this.touch();
    }
    getPeerCertificate(...args) { return socket.getPeerCertificate(...args); }
    setTimeout(milliseconds, callback) {
      if (!Number.isFinite(milliseconds) || milliseconds < 0 || milliseconds > 310000) throw new Error('Invalid mesh stream timeout');
      this.idleMilliseconds = milliseconds;
      if (callback) this.once('timeout', callback);
      this.touch(); return this;
    }
    touch() {
      clearTimeout(this.idleTimer);
      if (!this.destroyed && this.idleMilliseconds > 0) {
        this.idleTimer = setTimeout(() => { this.emit('timeout'); if (!this.destroyed) this.destroy(new Error('Mesh stream idle timeout')); }, this.idleMilliseconds);
        this.idleTimer.unref?.();
      }
    }
    _read() { this.replenish(); }
    replenish() {
      if (closed || this.destroyed || this.remoteEnded) return;
      const available = WINDOW - this.receiveCredit - this.readableLength;
      if (available <= 0) return;
      const bytes = Buffer.allocUnsafe(4); bytes.writeUInt32BE(available);
      if (send(CREDIT, this.id, bytes)) this.receiveCredit += available;
      else fail(new Error('Mesh credit queue limit'));
    }
    _write(chunk, encoding, callback) {
      if (closed || this.destroyed) { callback(new Error('Mesh link closed')); return; }
      if (this.bytes + chunk.length > STREAM_BYTES) { callback(new Error('Mesh stream byte limit')); return; }
      this.pendingWrite = { chunk, offset: 0, callback };
      flushWrites();
    }
    flushFrame() {
      const pending = this.pendingWrite;
      if (!pending || this.destroyed || !this.sendCredit || closed) return false;
      const count = Math.min(FRAME, pending.chunk.length - pending.offset, this.sendCredit);
      if (count === 0) { this.pendingWrite = undefined; pending.callback(); return true; }
      if (!canSend(count)) return false;
      if (this.bytes + count > STREAM_BYTES) { this.destroy(new Error('Mesh stream byte limit')); return false; }
      // Update before send: a custom Duplex may synchronously deliver its peer's response.
      this.sendCredit -= count; this.bytes += count; sentBytes += count;
      const data = pending.chunk.subarray(pending.offset, pending.offset + count); pending.offset += count;
      send(DATA, this.id, data); this.touch();
      if (pending.offset === pending.chunk.length) { this.pendingWrite = undefined; pending.callback(); }
      return true;
    }
    _final(callback) {
      if (closed) { callback(new Error('Mesh link closed')); return; }
      this.localEnded = true; control(END, this.id); callback();
    }
    _destroy(error, callback) {
      clearTimeout(this.idleTimer); clearTimeout(this.lifetime);
      streams.delete(this.id);
      retire(this.id, { credit: this.receiveCredit, ended: this.remoteEnded, bytes: this.bytes });
      if (!closed && !this.remoteReset && !(this.localEnded && this.remoteEnded)) control(RESET, this.id);
      const pending = this.pendingWrite; this.pendingWrite = undefined;
      if (pending) pending.callback(error || new Error('Mesh stream closed'));
      callback(error);
    }
    receive(data) {
      if (this.remoteEnded || data.length > this.receiveCredit) throw new Error('Mesh stream credit or end violation');
      if (this.bytes + data.length > STREAM_BYTES) throw new Error('Mesh stream byte limit');
      this.receiveCredit -= data.length; this.bytes += data.length; receivedBytes += data.length;
      this.touch(); this.push(data);
      // Flowing consumers may have consumed the chunk during push().
      this.replenish();
    }
  }
  function fail(error) {
    if (closed) return;
    closed = true; clearInterval(heartbeat);
    socket.off('data', receive); socket.off('drain', drained); socket.off('error', errored); socket.off('close', ended); socket.off('end', ended);
    receiving = Buffer.alloc(0); queue.length = 0; queueBytes = 0;
    for (const stream of [...streams.values()]) stream.destroy(error);
    streams.clear(); retiredStreams.clear(); socket.destroy();
    try { onClose?.(error); } catch { /* A caller callback cannot prevent cleanup. */ }
  }
  function handle(type, id, data) {
    if (type === PING || type === PONG) {
      if (id !== 0 || data.length !== 8) throw new Error('Invalid mesh heartbeat');
      if (type === PING) control(PONG, 0, data);
      else { if (!pendingPing || !pendingPing.equals(data)) throw new Error('Unexpected mesh heartbeat reply'); pendingPing = undefined; lastPong = Date.now(); }
      return;
    }
    if (!id || id > 0x7fffffff) throw new Error('Invalid mesh stream ID');
    if (type === OPEN) {
      if (data.length || id % 2 === localParity || id !== lastRemote + 2 || streams.has(id)) throw new Error('Invalid mesh stream open');
      lastRemote = id;
      if (streams.size >= 64) { retire(id, { credit: WINDOW, ended: false, bytes: 0 }); control(RESET, id); return; }
      const stream = new MeshStream(id); streams.set(id, stream); onStream(stream); return;
    }
    if (![DATA, END, RESET, CREDIT].includes(type)) throw new Error('Unknown mesh frame type');
    if ((type === END || type === RESET) && data.length !== 0 || type === CREDIT && data.length !== 4 || type === DATA && data.length === 0) throw new Error('Invalid mesh frame length');
    const stream = streams.get(id);
    // Frames already in flight when either peer resets a stream may safely be discarded.
    // Keep bounded tombstones: a reset does not grant unlimited unauthenticated traffic.
    if (!stream) {
      const previous = retiredStreams.get(id);
      if (!previous) throw new Error('Unknown mesh stream');
      if (type === DATA) {
        if (previous.ended || data.length > previous.credit || previous.bytes + data.length > STREAM_BYTES) throw new Error('Retired mesh stream credit or end violation');
        previous.credit -= data.length; previous.bytes += data.length;
      }
      if (type === END) { if (previous.ended) throw new Error('Duplicate retired mesh stream end'); previous.ended = true; }
      if (type === CREDIT && (!data.readUInt32BE(0) || data.readUInt32BE(0) > WINDOW)) throw new Error('Invalid retired mesh stream credit');
      return;
    }
    if (type === DATA) stream.receive(data);
    if (type === END) {
      if (stream.remoteEnded) throw new Error('Duplicate mesh stream end');
      stream.remoteEnded = true; stream.push(null);
    }
    if (type === RESET) { stream.remoteReset = true; stream.destroy(new Error('Mesh stream reset by peer')); }
    if (type === CREDIT) {
      const credit = data.readUInt32BE(0);
      if (!credit || stream.sendCredit + credit > WINDOW) throw new Error('Invalid mesh stream credit');
      stream.sendCredit += credit; flushWrites();
    }
  }
  function receive(chunk) {
    if (closed) return;
    try {
      if (receiving.length + chunk.length > QUEUE) throw new Error('Mesh receive buffer limit');
      receiving = receiving.length ? Buffer.concat([receiving, chunk]) : chunk;
      while (!closed && receiving.length >= 9) {
        const length = receiving.readUInt32BE(0);
        if (length > FRAME) throw new Error('Mesh frame too large');
        if (receiving.length < 9 + length) break;
        const type = receiving[8]; const id = receiving.readUInt32BE(4);
        const data = receiving.subarray(9, 9 + length);
        receiving = receiving.subarray(9 + length);
        handle(type, id, data);
      }
    } catch (error) { fail(error); }
  }
  function drained() { blocked = false; drainQueue(); flushWrites(); }
  function errored(error) { fail(error); }
  function ended() { fail(new Error('Mesh transport closed')); }
  const heartbeat = setInterval(() => {
    if (Date.now() - lastPong >= 45000) { fail(new Error('Mesh heartbeat timeout')); return; }
    if (!pendingPing) { pendingPing = randomBytes(8); control(PING, 0, pendingPing); }
  }, 15000);
  heartbeat.unref?.();
  socket.on('data', receive); socket.on('drain', drained); socket.on('error', errored); socket.once('close', ended); socket.once('end', ended); socket.resume();
  return {
    openStream() {
      if (closed) throw new Error('Mesh link closed');
      if (streams.size >= 64 || nextLocal > 0x7fffffff) throw new Error('Mesh stream limit');
      const id = nextLocal; nextLocal += 2;
      const stream = new MeshStream(id); streams.set(id, stream);
      if (!send(OPEN, id)) { stream.destroy(new Error('Mesh socket queue limit')); throw new Error('Mesh socket queue limit'); }
      return stream;
    },
    close() { fail(); },
    get closed() { return closed; },
    get stats() { return { streams: streams.size, queuedBytes: queuedBytes(), sentBytes, receivedBytes }; },
  };
}
