const APK_CONSTANT = fromHex('97CFB802844143DE56002B3B34780A5D');
const ZERO_IV = new Uint8Array(16);
function bytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) { return new Uint8Array(value.buffer, value.byteOffset, value.byteLength); }
  throw new TypeError('expected Uint8Array, ArrayBuffer or ArrayBuffer view');
}
export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) { throw new TypeError('invalid hex'); }
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < result.length; i++) { result[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16); }
  return result;
}
export function toHex(value) { return Array.from(bytes(value), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase(); }
export function concat(...parts) {
  const arrays = parts.map(bytes);
  const result = new Uint8Array(arrays.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of arrays) { result.set(part, offset); offset += part.length; }
  return result;
}
function subtle() { if (!globalThis.crypto?.subtle) { throw new Error('WebCrypto requires a secure context'); } return globalThis.crypto.subtle; }
async function importAesKey(raw) { return subtle().importKey('raw', raw, { name: 'AES-CBC' }, false, ['encrypt']); }
async function aesBlock(key, block) {
  const encrypted = await subtle().encrypt({ name: 'AES-CBC', iv: ZERO_IV }, key, block);
  return new Uint8Array(encrypted, 0, 16).slice();
}
function xorBlock(left, right) {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) result[i] = left[i] ^ right[i];
  return result;
}
function javaInt(counter) { if (!Number.isInteger(counter) || counter < -2147483648 || counter > 2147483647) { throw new RangeError('counter must be a Java int'); } }
function plainFrame(value) {
  const plain = bytes(value).slice();
  if (plain.length < 3) throw new RangeError('plain frame must include a 3-byte header');
  return plain;
}
export class AesSession {
  #first16; #b; #d = null; #initialization = null; #initialMask = null; #sessionKey = null; #destroyed = false; #generation = 0;
  #checkAlive(generation = this.#generation) {
    if (this.#destroyed || generation !== this.#generation) { throw new DOMException('Encryption session was destroyed or replaced', 'AbortError'); }
  }
  constructor(name) {
    if (name != null && typeof name !== 'string') throw new TypeError('name must be a string or null');
    const ascii = Uint8Array.from(Array.from(name ?? '', character => { const code = character.codePointAt(0); return code <= 0x7F ? code : 0x3F; }));
    this.#first16 = new Uint8Array(16); this.#first16.set(ascii.subarray(0, 16));
    this.#b = ascii.length > 16 ? ascii.slice(-16) : this.#first16.slice();
  }
  async establishPairing(authParam16) { await this.establish(this.#b, authParam16); }
  destroy() {
    this.#destroyed = true; this.#generation++;
    this.#first16.fill(0); this.#b.fill(0); this.#d?.fill(0); this.#initialMask?.fill(0);
    this.#d = null; this.#initialMask = null; this.#sessionKey = null; this.#initialization = null;
  }
  async init() {
    this.#checkAlive();
    if (!this.#initialization) {
      this.#initialization = (async () => {
        const digest = await subtle().digest('SHA-1', concat(this.#first16, APK_CONSTANT));
        this.#checkAlive();
        const key = await importAesKey(new Uint8Array(digest, 0, 16));
        this.#checkAlive();
        const mask = await aesBlock(key, APK_CONSTANT);
        if (this.#destroyed) { mask.fill(0); this.#checkAlive(); }
        this.#initialMask = mask;
      })();
    }
    await this.#initialization; this.#checkAlive(); return this;
  }
  #requireInit() { this.#checkAlive(); if (!this.#initialMask) throw new Error('session not initialized; await init() first'); }
  #requireSession() { this.#checkAlive(); if (!this.#sessionKey || !this.#d) throw new Error('session not established'); }
  async encryptInitial(value) {
    this.#requireInit();
    const plain = bytes(value).slice();
    if (plain.length < 7 || plain[0] !== 0x5A || plain[1] !== 0xA5) { throw new RangeError('invalid plain frame'); }
    const body = plain.subarray(3);
    const encrypted = new Uint8Array(body.length);
    let sum = 0;
    for (let i = 0; i < body.length; i++) { encrypted[i] = body[i] ^ this.#initialMask[i & 15]; sum = (sum + body[i]) & 0xFFFF; }
    const complemented = (~sum) & 0xFFFF;
    return concat(plain.subarray(0, 3), encrypted, Uint8Array.of(0, 0, complemented & 0xFF, complemented >>> 8, 0, 0));
  }
  async decryptInitial(value) {
    this.#requireInit();
    const frame = bytes(value).slice();
    if (frame.length < 9) throw new RangeError('short Enc2 frame');
    const plain = frame.slice(0, -6);
    for (let i = 3; i < plain.length; i++) plain[i] ^= this.#initialMask[(i - 3) & 15];
    return plain;
  }
  async establish(password16, authParam16) {
    this.#requireInit();
    if (password16 == null || bytes(password16).length !== 16) { throw new RangeError('password must be 16 bytes'); }
    if (authParam16 == null || bytes(authParam16).length !== 16) { throw new RangeError('authParam must be 16 bytes'); }
    const password = bytes(password16).slice();
    const authParam = bytes(authParam16).slice();
    const generation = ++this.#generation;
    let committed = false;
    try {
      const digest = await subtle().digest('SHA-1', concat(password, authParam));
      this.#checkAlive(generation);
      const key = await importAesKey(new Uint8Array(digest, 0, 16));
      this.#checkAlive(generation);
      this.#d?.fill(0); this.#d = authParam; this.#sessionKey = key; committed = true;
    } finally { password.fill(0); if (!committed) authParam.fill(0); }
  }
  nonce(counter) {
    this.#requireSession(); javaInt(counter);
    const result = new Uint8Array(13);
    result[2] = (counter >>> 8) & 0xFF; result[3] = counter & 0xFF;
    result.set(this.#d.subarray(0, 8), 4); return result;
  }
  async counterXor(counter, value) {
    const nonce = this.nonce(counter);
    const generation = this.#generation;
    const key = this.#sessionKey;
    const body = bytes(value).slice();
    const result = new Uint8Array(body.length);
    for (let offset = 0, blockIndex = 1; offset < body.length; offset += 16, blockIndex++) {
      const block = new Uint8Array(16);
      block[0] = 1; block.set(nonce, 1);
      block[15] = blockIndex & 0xFF;
      const mask = await aesBlock(key, block);
      this.#checkAlive(generation);
      for (let i = 0; i < Math.min(16, body.length - offset); i++) { result[offset + i] = body[offset + i] ^ mask[i]; }
    }
    return result;
  }
  async mac(counter, value) {
    const nonce = this.nonce(counter);
    const generation = this.#generation;
    const key = this.#sessionKey;
    const plain = plainFrame(value);
    const body = plain.subarray(3);
    const block = new Uint8Array(16);
    block[0] = 0x59; block.set(nonce, 1);
    block[15] = body.length & 0xFF;
    let state = await aesBlock(key, block);
    this.#checkAlive(generation);
    const header = new Uint8Array(16); header.set(plain.subarray(0, 3));
    state = await aesBlock(key, xorBlock(state, header));
    this.#checkAlive(generation);
    for (let offset = 0; offset < body.length; offset += 16) {
      const padded = new Uint8Array(16); padded.set(body.subarray(offset, offset + 16));
      state = await aesBlock(key, xorBlock(state, padded));
      this.#checkAlive(generation);
    }
    block[0] = 1; block[15] = 0;
    const mask = await aesBlock(key, block);
    this.#checkAlive(generation);
    const tag = new Uint8Array(4);
    for (let i = 0; i < 4; i++) tag[i] = state[i] ^ mask[i];
    return tag;
  }
  async encrypt(counter, value) {
    this.#requireSession();
    if (!Number.isInteger(counter) || counter < 1 || counter > 0xFFFF) { throw new RangeError('counter out of range'); }
    const generation = this.#generation;
    const plain = plainFrame(value);
    const [body, tag] = await Promise.all([
      this.counterXor(counter, plain.subarray(3)),
      this.mac(counter, plain),
    ]);
    this.#checkAlive(generation);
    return concat(plain.subarray(0, 3), body, tag, Uint8Array.of(counter >>> 8, counter & 0xFF));
  }
  async decrypt(value) {
    this.#requireSession();
    const generation = this.#generation;
    const frame = bytes(value).slice();
    if (frame.length < 9) throw new RangeError('short Enc2 frame');
    const counter = (frame[frame.length - 2] << 8) | frame[frame.length - 1];
    const body = await this.counterXor(counter, frame.subarray(3, frame.length - 6));
    this.#checkAlive(generation);
    const plain = concat(frame.subarray(0, 3), body);
    const expected = await this.mac(counter, plain);
    this.#checkAlive(generation);
    let difference = 0;
    for (let i = 0; i < 4; i++) difference |= expected[i] ^ frame[frame.length - 6 + i];
    return { counter, valid: difference === 0, plain };
  }
}
