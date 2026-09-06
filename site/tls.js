/*
 * tls.js - decrypts the recorded HTTPS sessions in the browser, the same way
 * Wireshark does when you give it a key log file. Nothing here is a shortcut:
 * the TCP streams are reassembled from the packets, the session keys are
 * derived from the secrets in the key log, and each TLS record is opened with
 * AES-GCM through the browser's WebCrypto API.
 *
 * Supported: TLS 1.2 with AES-GCM ciphers (via CLIENT_RANDOM lines) and
 * TLS 1.3 with AES-GCM ciphers (via the *_TRAFFIC_SECRET lines).
 *
 * decryptCapture(packets, keylogText) -> Promise of
 *   [ { client, server, version, cipher, status, messages: [ { dir, no, kind, title, text } ] } ]
 */
(function (root) {
  'use strict';

  var subtle = (root.crypto || (typeof require === 'function' && require('crypto').webcrypto)).subtle;
  var enc = new TextEncoder(), dec = new TextDecoder('utf-8', { fatal: false });

  function hexToBytes(h) { var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function concat() { var n = 0, i; for (i = 0; i < arguments.length; i++) n += arguments[i].length; var out = new Uint8Array(n), o = 0; for (i = 0; i < arguments.length; i++) { out.set(arguments[i], o); o += arguments[i].length; } return out; }
  function u16(b, o) { return (b[o] << 8) | b[o + 1]; }

  async function hmac(hash, key, data) {
    var k = await subtle.importKey('raw', key, { name: 'HMAC', hash: hash }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', k, data));
  }

  /* TLS 1.2 PRF: P_hash(secret, label + seed) */
  async function prf12(hash, secret, label, seed, len) {
    var ls = concat(enc.encode(label), seed), out = new Uint8Array(0), a = ls;
    while (out.length < len) { a = await hmac(hash, secret, a); out = concat(out, await hmac(hash, secret, concat(a, ls))); }
    return out.slice(0, len);
  }

  /* TLS 1.3 HKDF-Expand-Label */
  async function hkdfExpandLabel(hash, secret, label, len) {
    var full = enc.encode('tls13 ' + label);
    var info = concat(new Uint8Array([len >> 8, len & 255, full.length]), full, new Uint8Array([0]));
    var out = new Uint8Array(0), t = new Uint8Array(0), i = 1;
    while (out.length < len) { t = await hmac(hash, secret, concat(t, info, new Uint8Array([i++]))); out = concat(out, t); }
    return out.slice(0, len);
  }

  var SUITES = {
    0x009c: { name: 'RSA-AES128-GCM-SHA256', hash: 'SHA-256', keyLen: 16, v13: false },
    0x009d: { name: 'RSA-AES256-GCM-SHA384', hash: 'SHA-384', keyLen: 32, v13: false },
    0xc02f: { name: 'ECDHE-RSA-AES128-GCM-SHA256', hash: 'SHA-256', keyLen: 16, v13: false },
    0xc030: { name: 'ECDHE-RSA-AES256-GCM-SHA384', hash: 'SHA-384', keyLen: 32, v13: false },
    0xc02b: { name: 'ECDHE-ECDSA-AES128-GCM-SHA256', hash: 'SHA-256', keyLen: 16, v13: false },
    0xc02c: { name: 'ECDHE-ECDSA-AES256-GCM-SHA384', hash: 'SHA-384', keyLen: 32, v13: false },
    0x1301: { name: 'TLS_AES_128_GCM_SHA256', hash: 'SHA-256', keyLen: 16, v13: true },
    0x1302: { name: 'TLS_AES_256_GCM_SHA384', hash: 'SHA-384', keyLen: 32, v13: true }
  };

  function parseKeylog(text) {
    var byRandom = {};
    text.split(/\r?\n/).forEach(function (line) {
      var m = line.trim().split(/\s+/);
      if (m.length !== 3 || line[0] === '#') return;
      var r = m[1].toLowerCase();
      byRandom[r] = byRandom[r] || {};
      byRandom[r][m[0]] = hexToBytes(m[2]);
    });
    return byRandom;
  }

  /* One direction of a TCP connection: bytes in sequence order, remembering
   * which packet each byte came from. */
  function buildStream(pkts) {
    var chunks = pkts.filter(function (p) { return p.payload && p.payload.length; })
      .sort(function (a, b) { return (a.tcp.seq - b.tcp.seq) || (a.no - b.no); });
    var out = [], marks = [], expected = null, total = 0;
    chunks.forEach(function (p) {
      var seq = p.tcp.seq, data = p.payload;
      if (expected !== null) {
        if (seq < expected) { var skip = expected - seq; if (skip >= data.length) return; data = data.slice(skip); seq = expected; } /* retransmission */
      }
      marks.push({ start: total, no: p.no });
      out.push(data); total += data.length; expected = seq + data.length;
    });
    var bytes = concat.apply(null, out);
    return { bytes: bytes, packetAt: function (off) { var no = marks.length ? marks[0].no : 0; marks.forEach(function (m) { if (m.start <= off) no = m.no; }); return no; } };
  }

  async function aesGcmOpen(keyBytes, nonce, aad, ct) {
    var key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, ct));
  }

  function seqBytes(n, len) { var b = new Uint8Array(len); for (var i = 0; i < 8 && i < len; i++) b[len - 1 - i] = Math.floor(n / Math.pow(2, 8 * i)) & 255; return b; }

  /* Walk one direction of a connection, decrypting what can be decrypted. */
  async function walkDirection(dir, stream, keys, suite, v13, messages, statusOut) {
    var b = stream.bytes, pos = 0, encrypted = false, seq = 0, phase = 'handshake', writeKey = null, writeIv = null;
    var textOut = { app: [] };
    while (pos + 5 <= b.length) {
      var type = b[pos], ver = u16(b, pos + 1), len = u16(b, pos + 3), body = pos + 5, no = stream.packetAt(pos);
      if (body + len > b.length) break;
      var rec = b.slice(body, body + len);
      if (!encrypted) {
        if (type === 20 && !v13) { encrypted = true; seq = 0; writeKey = keys.app.key; writeIv = keys.app.iv; }
        else if (type === 22) {
          messages.push({ dir: dir, no: no, kind: 'clear', title: 'Handshake (sent in the clear)', text: handshakeNames(rec) });
          /* TLS 1.3: everything after each side's Hello is encrypted with the handshake keys */
          if (v13) { writeKey = keys.hs.key; writeIv = keys.hs.iv; encrypted = true; seq = 0; }
        }
        pos = body + len; continue;
      }
      if (v13 && type === 20) { pos = body + len; continue; }   /* TLS 1.3 "compatibility" CCS: means nothing */
      var plain, innerType = type;
      try {
        if (v13) {
          var nonce = writeIv.slice(); var s = seqBytes(seq, 12); for (var i = 0; i < 12; i++) nonce[i] ^= s[i];
          plain = await aesGcmOpen(writeKey, nonce, b.slice(pos, pos + 5), rec);
          var end = plain.length - 1; while (end > 0 && plain[end] === 0) end--;
          innerType = plain[end]; plain = plain.slice(0, end);
        } else {
          var nonce12 = concat(writeIv, rec.slice(0, 8)), ct = rec.slice(8), plen = len - 8 - 16;
          var aad = concat(seqBytes(seq, 8), new Uint8Array([type, ver >> 8, ver & 255, plen >> 8, plen & 255]));
          plain = await aesGcmOpen(writeKey, nonce12, aad, ct);
        }
      } catch (e) {
        messages.push({ dir: dir, no: no, kind: 'fail', title: 'Could not decrypt record', text: 'record type ' + type + ', ' + len + ' bytes (wrong key or unsupported cipher)' });
        statusOut.failed++; pos = body + len; seq++; continue;
      }
      seq++;
      if (innerType === 22) {
        var names = handshakeNames(plain);
        messages.push({ dir: dir, no: no, kind: 'handshake', title: 'Handshake (decrypted)', text: names });
        if (v13 && /Finished/.test(names) && phase === 'handshake') { phase = 'app'; writeKey = keys.app.key; writeIv = keys.app.iv; seq = 0; }
      } else if (innerType === 21) {
        messages.push({ dir: dir, no: no, kind: 'alert', title: 'Alert (decrypted)', text: plain.length >= 2 ? (ALERTS[plain[1]] || 'alert ' + plain[1]) + (plain[0] === 2 ? ' (fatal)' : ' (warning)') : 'alert' });
      } else if (innerType === 23) {
        textOut.app.push({ no: no, bytes: plain });
        statusOut.decrypted++;
      }
      pos = body + len;
    }
    return textOut.app;
  }

  var ALERTS = { 0: 'close_notify: "I am finished, closing politely"', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 42: 'bad_certificate', 46: 'certificate_unknown', 48: 'unknown_ca', 50: 'decode_error: "I could not make sense of what you sent" (here: the browser closed the socket mid-handshake)', 80: 'internal_error', 90: 'user_canceled', 112: 'unrecognized_name' };
  var HS = { 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
  function handshakeNames(b) {
    var o = 0, out = [];
    while (o + 4 <= b.length) { var t = b[o], l = (b[o + 1] << 16) | u16(b, o + 2); out.push((HS[t] || 'type ' + t) + ' (' + l + ' bytes)'); o += 4 + l; }
    return out.join(', ');
  }

  /* Turn a direction's decrypted bytes into HTTP messages (headers + body). */
  async function splitHttp(chunks, dir) {
    var all = concat.apply(null, chunks.map(function (c) { return c.bytes; }));
    var startNo = function (off) { var no = chunks.length ? chunks[0].no : 0, t = 0; chunks.forEach(function (c) { if (t <= off) no = c.no; t += c.bytes.length; }); return no; };
    var msgs = [], pos = 0, text = latin1(all);
    while (pos < all.length) {
      var he = text.indexOf('\r\n\r\n', pos);
      if (he < 0) { msgs.push({ dir: dir, no: startNo(pos), kind: 'http', title: dir === 'client' ? 'Request (decrypted)' : 'Response (decrypted)', text: text.slice(pos), body: '' }); break; }
      var head = text.slice(pos, he), lines = head.split('\r\n'), hdr = {};
      lines.slice(1).forEach(function (l) { var i = l.indexOf(':'); if (i > 0) hdr[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); });
      var bodyStart = he + 4, bodyBytes, next;
      if (hdr['transfer-encoding'] === 'chunked') {
        var parts = [], q = bodyStart;
        while (q < all.length) { var le = text.indexOf('\r\n', q); var n = parseInt(text.slice(q, le), 16); if (!n) { q = le + 4; break; } parts.push(all.slice(le + 2, le + 2 + n)); q = le + 2 + n + 2; }
        bodyBytes = concat.apply(null, parts); next = q;
      } else {
        var cl = hdr['content-length'] !== undefined ? parseInt(hdr['content-length'], 10) : (dir === 'client' ? 0 : all.length - bodyStart);
        bodyBytes = all.slice(bodyStart, bodyStart + cl); next = bodyStart + cl;
      }
      var bodyText = '', note = '';
      if (bodyBytes.length) {
        if (/gzip|br|deflate|zstd/.test(hdr['content-encoding'] || '')) {
          try { bodyBytes = await inflate(bodyBytes, hdr['content-encoding']); note = 'body was ' + hdr['content-encoding'] + '-compressed on the wire; unpacked here'; }
          catch (e) { note = 'body is ' + hdr['content-encoding'] + '-compressed (' + bodyBytes.length + ' bytes); this browser could not unpack it'; }
        }
        bodyText = dec.decode(bodyBytes);
      }
      msgs.push({ dir: dir, no: startNo(pos), kind: 'http', title: (dir === 'client' ? 'Request' : 'Response') + ' (decrypted)', text: head, body: bodyText, note: note, contentType: hdr['content-type'] || '' });
      pos = next;
    }
    return msgs;
  }
  function latin1(b) { var s = ''; for (var i = 0; i < b.length; i += 8192) s += String.fromCharCode.apply(null, b.subarray(i, i + 8192)); return s; }
  async function inflate(bytes, encoding) {
    if (typeof DecompressionStream === 'undefined') throw new Error('no DecompressionStream');
    var fmt = encoding === 'gzip' ? 'gzip' : encoding === 'deflate' ? 'deflate' : null;
    if (!fmt) throw new Error('unsupported');
    var ds = new DecompressionStream(fmt), w = ds.writable.getWriter(); w.write(bytes); w.close();
    return new Uint8Array(await new Response(ds.readable).arrayBuffer());
  }

  async function decryptCapture(packets, keylogText) {
    var secrets = parseKeylog(keylogText), conns = {}, order = [];
    packets.forEach(function (p) {
      if (!p.tcp || !(p.sport === 443 || p.dport === 443)) return;
      var client = p.dport === 443 ? p.src + ':' + p.sport : p.dst + ':' + p.dport;
      var server = p.dport === 443 ? p.dst + ':' + p.dport : p.src + ':' + p.sport;
      var k = client + '>' + server;
      if (!conns[k]) { conns[k] = { client: client, server: server, c2s: [], s2c: [], first: p.no }; order.push(k); }
      var c = conns[k];
      (p.dport === 443 ? c.c2s : c.s2c).push(p);
      if (p.tlsClientRandom) c.clientRandom = p.tlsClientRandom;
      if (p.tlsNegotiated) { c.serverRandom = p.tlsServerRandom; c.cipher = p.tlsCipher; c.version = p.tlsNegotiated; }
    });
    var results = [];
    for (var i = 0; i < order.length; i++) {
      var c = conns[order[i]], suite = SUITES[c.cipher], r = { client: c.client, server: c.server, firstPacket: c.first, version: c.version || '?', cipher: suite ? suite.name : (c.cipher !== undefined ? '0x' + c.cipher.toString(16) : 'unknown'), messages: [], decrypted: 0, failed: 0 };
      results.push(r);
      if (!c.clientRandom || !c.version) { r.status = 'No handshake in the capture for this connection.'; continue; }
      var s = secrets[c.clientRandom];
      if (!s) { r.status = 'No line in the key log for client random ' + c.clientRandom.slice(0, 16) + '...; this connection stays encrypted.'; continue; }
      if (!suite) { r.status = 'Cipher ' + r.cipher + ' is not one this page can open (only AES-GCM is supported here; Wireshark can do more).'; continue; }
      var keys = { client: {}, server: {} };
      try {
        if (suite.v13) {
          if (!s.CLIENT_HANDSHAKE_TRAFFIC_SECRET || !s.CLIENT_TRAFFIC_SECRET_0) { r.status = 'The key log has no TLS 1.3 traffic secrets for this connection.'; continue; }
          var pairs = [['client', 'hs', s.CLIENT_HANDSHAKE_TRAFFIC_SECRET], ['server', 'hs', s.SERVER_HANDSHAKE_TRAFFIC_SECRET], ['client', 'app', s.CLIENT_TRAFFIC_SECRET_0], ['server', 'app', s.SERVER_TRAFFIC_SECRET_0]];
          for (var j = 0; j < pairs.length; j++) keys[pairs[j][0]][pairs[j][1]] = { key: await hkdfExpandLabel(suite.hash, pairs[j][2], 'key', suite.keyLen), iv: await hkdfExpandLabel(suite.hash, pairs[j][2], 'iv', 12) };
        } else {
          if (!s.CLIENT_RANDOM) { r.status = 'The key log has no CLIENT_RANDOM line for this connection.'; continue; }
          var kb = await prf12(suite.hash, s.CLIENT_RANDOM, 'key expansion', concat(hexToBytes(c.serverRandom), hexToBytes(c.clientRandom)), suite.keyLen * 2 + 8);
          keys.client.app = { key: kb.slice(0, suite.keyLen), iv: kb.slice(suite.keyLen * 2, suite.keyLen * 2 + 4) };
          keys.server.app = { key: kb.slice(suite.keyLen, suite.keyLen * 2), iv: kb.slice(suite.keyLen * 2 + 4, suite.keyLen * 2 + 8) };
        }
        var stat = { decrypted: 0, failed: 0 };
        var cApp = await walkDirection('client', buildStream(c.c2s), keys.client, suite, suite.v13, r.messages, stat);
        var sApp = await walkDirection('server', buildStream(c.s2c), keys.server, suite, suite.v13, r.messages, stat);
        r.decrypted = stat.decrypted; r.failed = stat.failed;
        var http = (await splitHttp(cApp, 'client')).concat(await splitHttp(sApp, 'server'));
        r.messages = r.messages.concat(http).sort(function (a, b) { return a.no - b.no; });
        r.status = stat.failed ? stat.failed + ' record(s) could not be opened.' : (stat.decrypted ? 'Decrypted ' + stat.decrypted + ' application-data record(s).' : 'Handshake only; no application data was sent on this connection.');
      } catch (e) { r.status = 'Error while decrypting: ' + (e && e.message ? e.message : e); }
    }
    return results;
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { decryptCapture: decryptCapture, parseKeylog: parseKeylog };
  else root.decryptCapture = decryptCapture;
})(typeof window !== 'undefined' ? window : globalThis);
