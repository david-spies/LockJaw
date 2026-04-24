/**
 * LockJaw Browser Client
 * Handles WebSocket connection, UI state, and the crypto pipeline
 * (mirrors crypto/engine.py in pure JS — no server-side decryption)
 */

// ── Morse Table ──────────────────────────────────────────────────────────
const MORSE_ENCODE = {
  A:'.-', B:'-...', C:'-.-.', D:'-..', E:'.', F:'..-.', G:'--.', H:'....', I:'..',
  J:'.---', K:'-.-', L:'.-..', M:'--', N:'-.', O:'---', P:'.--.', Q:'--.-', R:'.-.',
  S:'...', T:'-', U:'..-', V:'...-', W:'.--', X:'-..-', Y:'-.--', Z:'--..',
  0:'-----', 1:'.----', 2:'..---', 3:'...--', 4:'....-', 5:'.....',
  6:'-....', 7:'--...', 8:'---..', 9:'----.',
  '.':'.-.-.-', ',':'--..--', '?':'..--..', '/':'-..-.', ' ':' ',
};
const MORSE_DECODE = Object.fromEntries(Object.entries(MORSE_ENCODE).map(([k,v]) => [v,k]));

// ── Layer A: Morse-ASCII ─────────────────────────────────────────────────

function textToMorseBinary(text) {
  const bytes = [];
  for (const char of text.toUpperCase()) {
    if (char === ' ') { bytes.push(3); continue; }
    const morse = MORSE_ENCODE[char];
    if (!morse) continue;
    for (const c of morse) bytes.push(c === '.' ? 0 : 1);
    bytes.push(2);
  }
  return new Uint8Array(bytes);
}

function morseBinaryToText(data) {
  let result = '';
  let current = [];
  for (const byte of data) {
    if (byte === 2) {
      if (current.length) {
        const morse = current.map(b => b === 0 ? '.' : '-').join('');
        result += MORSE_DECODE[morse] || '?';
        current = [];
      }
    } else if (byte === 3) {
      if (current.length) {
        const morse = current.map(b => b === 0 ? '.' : '-').join('');
        result += MORSE_DECODE[morse] || '?';
        current = [];
      }
      result += ' ';
    } else {
      current.push(byte);
    }
  }
  if (current.length) {
    const morse = current.map(b => b === 0 ? '.' : '-').join('');
    result += MORSE_DECODE[morse] || '?';
  }
  return result.trim();
}

// ── Layer B: Beale XOR (HMAC-SHA256 keystream) ───────────────────────────

async function bealeKeystream(phrase, iv, length) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(phrase), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const prk = await crypto.subtle.sign('HMAC', keyMaterial, iv);
  let stream = new Uint8Array(0);
  let counter = 0;
  while (stream.length < length) {
    const ctrBuf = new Uint8Array(4);
    new DataView(ctrBuf.buffer).setUint32(0, counter, false);
    const kMat = await crypto.subtle.importKey(
      'raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const block = new Uint8Array(await crypto.subtle.sign('HMAC', kMat, ctrBuf));
    const merged = new Uint8Array(stream.length + block.length);
    merged.set(stream); merged.set(block, stream.length);
    stream = merged;
    counter++;
  }
  return stream.slice(0, length);
}

async function bealeXor(data, phrase, iv) {
  const ks = await bealeKeystream(phrase, iv, data.length);
  return data.map((b, i) => b ^ ks[i]);
}

// ── Layer C: AES-256-GCM ─────────────────────────────────────────────────

async function deriveAesKey(machineId, totpCode, phrase) {
  const enc = new TextEncoder();
  // HMAC-SHA256(machineId, totpCode) → PBKDF2 with phrase
  const hmacKey = await crypto.subtle.importKey(
    'raw', enc.encode(machineId), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const identityHash = new Uint8Array(
    await crypto.subtle.sign('HMAC', hmacKey, enc.encode(totpCode))
  );
  const baseKey = await crypto.subtle.importKey('raw', identityHash, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(phrase), iterations: 100_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ── Envelope serialization ────────────────────────────────────────────────

function packEnvelope(nonce, bealeIv, ciphertext) {
  // header(3) + nonce(12) + bealeIv(8) + ciphertext(n)
  // AES-GCM appends the 16-byte tag at the end of ciphertext
  const buf = new Uint8Array(3 + 12 + 8 + ciphertext.byteLength);
  const view = new DataView(buf.buffer);
  view.setUint8(0, 2);                          // version
  view.setUint16(1, ciphertext.byteLength, false);
  buf.set(nonce, 3);
  buf.set(bealeIv, 15);
  buf.set(new Uint8Array(ciphertext), 23);
  return btoa(String.fromCharCode(...buf));
}

function unpackEnvelope(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const view = new DataView(raw.buffer);
  const ctLen = view.getUint16(1, false);
  return {
    version:    view.getUint8(0),
    nonce:      raw.slice(3, 15),
    bealeIv:    raw.slice(15, 23),
    ciphertext: raw.slice(23, 23 + ctLen),
  };
}

// ── Public encrypt/decrypt ────────────────────────────────────────────────

async function lockjawEncrypt(plaintext, phrase, totpCode, machineId) {
  const morseBytes  = textToMorseBinary(plaintext);
  const bealeIv     = crypto.getRandomValues(new Uint8Array(8));
  const bealeXored  = await bealeXor(morseBytes, phrase, bealeIv);
  const aesKey      = await deriveAesKey(machineId, totpCode, phrase);
  const nonce       = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext  = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aesKey, bealeXored
  );
  return packEnvelope(nonce, bealeIv, ciphertext);
}

async function lockjawDecrypt(b64, phrase, totpCode, machineId) {
  const { nonce, bealeIv, ciphertext } = unpackEnvelope(b64);
  const aesKey   = await deriveAesKey(machineId, totpCode, phrase);
  const bealeXored = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ciphertext)
  );
  const morseBytes = await bealeXor(bealeXored, phrase, bealeIv);
  return morseBinaryToText(morseBytes);
}

// ── TOTP (RFC 6238, SHA-1, 30s) ──────────────────────────────────────────

async function generateTOTP(secretBytes, window = null) {
  if (window === null) window = Math.floor(Date.now() / 30_000);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(window), false);
  const key = await crypto.subtle.importKey(
    'raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = hmac[19] & 0x0F;
  const view = new DataView(hmac.buffer);
  const code = (view.getUint32(offset, false) & 0x7FFFFFFF) % 1_000_000;
  return String(code).padStart(6, '0');
}

// ── WebSocket client state ────────────────────────────────────────────────

const LockJaw = {
  ws:        null,
  nodeId:    '',
  phrase:    '',
  totpCode:  '',
  machineId: '',
  onMessage: null,   // callback(from, plaintext, ciphertext)
  onPresence: null,  // callback(event, nodeId)

  async connect(serverUrl, nodeId, phrase, totpCode) {
    this.nodeId   = nodeId;
    this.phrase   = phrase;
    this.totpCode = totpCode;
    this.machineId = nodeId;

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(serverUrl);
      this.ws.onopen = () => {
        this.ws.send(JSON.stringify({ type: 'hello', node_id: nodeId }));
      };
      this.ws.onmessage = async (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'welcome') return resolve(msg);
        if (msg.type === 'error')   return reject(new Error(msg.msg));
        await this._handleMsg(msg);
      };
      this.ws.onerror = (e) => reject(e);
    });
  },

  async _handleMsg(msg) {
    if (msg.type === 'message') {
      try {
        const plaintext = await lockjawDecrypt(
          msg.ciphertext, this.phrase, this.totpCode, msg.from
        );
        this.onMessage?.(msg.from, plaintext, msg.ciphertext);
      } catch {
        this.onMessage?.(msg.from, '[decryption failed]', msg.ciphertext);
      }
    } else if (msg.type === 'presence') {
      this.onPresence?.(msg.event, msg.node);
    }
  },

  async send(targetId, plaintext) {
    const b64 = await lockjawEncrypt(plaintext, this.phrase, this.totpCode, this.nodeId);
    this.ws.send(JSON.stringify({ type: 'send', to: targetId, ciphertext: b64 }));
    return b64;
  },

  close() {
    this.ws?.close();
  },
};

// Export for Node.js / bundlers
if (typeof module !== 'undefined') {
  module.exports = {
    LockJaw,
    lockjawEncrypt,
    lockjawDecrypt,
    generateTOTP,
    textToMorseBinary,
    morseBinaryToText,
  };
}
