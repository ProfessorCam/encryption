/*
 * pcap.js - a deliberately small libpcap parser for teaching.
 *
 * Understands: libpcap file format (not pcapng), Ethernet II, ARP, IPv4,
 * ICMP, UDP (with DNS, DHCP and TFTP decoding), TCP (with HTTP first-line decoding
 * and TLS record / handshake decoding on port 443).
 *
 * parsePcap(arrayBuffer) -> array of packets:
 *   { no, time, src, dst, proto, len, info, details: [ { title, rows: [[k, v], ...] } ] }
 *
 * Works in the browser (window.parsePcap) and in node (module.exports).
 */
(function (root) {
  'use strict';

  /* ---------- small helpers ---------- */

  function hex(n, width) {
    return '0x' + n.toString(16).padStart(width || 0, '0');
  }
  function mac(b, o) {
    var s = [];
    for (var i = 0; i < 6; i++) s.push(b[o + i].toString(16).padStart(2, '0'));
    return s.join(':');
  }
  function ip4(b, o) {
    return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3];
  }
  function u16(b, o) { return (b[o] << 8) | b[o + 1]; }
  function u32(b, o) { return ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]; }
  function ascii(b, o, n) {
    var s = '';
    for (var i = 0; i < n && o + i < b.length; i++) s += String.fromCharCode(b[o + i]);
    return s;
  }
  function isPrintable(b, o, n) {
    for (var i = 0; i < n && o + i < b.length; i++) {
      var c = b[o + i];
      if (c === 9 || c === 10 || c === 13) continue;
      if (c < 32 || c > 126) return false;
    }
    return true;
  }
  function section(title, rows) { return { title: title, rows: rows }; }

  /* TFTP only uses port 69 for the first packet; after that each transfer
   * runs between two freshly chosen ports. Remember which client endpoints
   * started a transfer so the later packets can be recognised. */
  var tftpSessions = {};

  /* ---------- file level ---------- */

  function parsePcap(buffer) {
    var bytes = new Uint8Array(buffer);
    var dv = new DataView(buffer);
    if (bytes.length < 24) throw new Error('File too short to be a pcap');
    var magic = dv.getUint32(0, false);
    var le, nano;
    switch (magic) {
      case 0xa1b2c3d4: le = false; nano = false; break;
      case 0xd4c3b2a1: le = true;  nano = false; break;
      case 0xa1b23c4d: le = false; nano = true;  break;
      case 0x4d3cb2a1: le = true;  nano = true;  break;
      case 0x0a0d0d0a: throw new Error('This is a pcapng file. Save it as classic pcap (File > Save As in Wireshark).');
      default: throw new Error('Not a libpcap file (magic ' + hex(magic, 8) + ')');
    }
    var linkType = dv.getUint32(20, le);
    if (linkType !== 1) throw new Error('Only Ethernet captures are supported (link type ' + linkType + ')');

    var packets = [];
    var off = 24, no = 1, t0 = null;
    tftpSessions = {}; tlsPending = {}; tlsEncrypted = {};
    while (off + 16 <= bytes.length) {
      var sec = dv.getUint32(off, le);
      var frac = dv.getUint32(off + 4, le);
      var incl = dv.getUint32(off + 8, le);
      var orig = dv.getUint32(off + 12, le);
      off += 16;
      if (off + incl > bytes.length) break;
      var ts = sec + frac / (nano ? 1e9 : 1e6);
      if (t0 === null) t0 = ts;
      var frame = bytes.subarray(off, off + incl);
      off += incl;

      var p;
      try {
        p = decodeEthernet(frame);
      } catch (e) {
        p = { src: '?', dst: '?', proto: '?', info: 'Could not decode frame: ' + e.message, details: [] };
      }
      p.no = no++;
      p.time = ts - t0;
      p.abs = ts;
      p.len = orig;
      packets.push(p);
    }
    makeTcpSeqRelative(packets);
    return packets;
  }

  /* ---------- layer 2 ---------- */

  function decodeEthernet(b) {
    var dst = mac(b, 0), src = mac(b, 6), type = u16(b, 12);
    var typeName = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6' }[type] || 'Unknown';
    var p = {
      src: src, dst: dst, proto: typeName, info: 'Ethertype ' + hex(type, 4),
      details: [section('Ethernet II', [
        ['Destination MAC', dst + (dst === 'ff:ff:ff:ff:ff:ff' ? '  (broadcast: everyone on the LAN)' : '')],
        ['Source MAC', src],
        ['Type', typeName + ' (' + hex(type, 4) + ')']
      ])]
    };
    p.srcMac = src; p.dstMac = dst;
    if (type === 0x0806) decodeArp(p, b, 14);
    else if (type === 0x0800) decodeIPv4(p, b, 14);
    return p;
  }

  function decodeArp(p, b, o) {
    var op = u16(b, o + 6);
    var sha = mac(b, o + 8), spa = ip4(b, o + 14), tha = mac(b, o + 18), tpa = ip4(b, o + 24);
    p.proto = 'ARP';
    p.arp = { op: op, sha: sha, spa: spa, tha: tha, tpa: tpa };
    var opName = op === 1 ? 'request' : op === 2 ? 'reply' : 'opcode ' + op;
    if (op === 1) {
      if (spa === tpa) p.info = 'Gratuitous ARP for ' + tpa + ' (announcing itself)';
      else if (spa === '0.0.0.0') p.info = 'ARP Probe: is anyone using ' + tpa + '?';
      else p.info = 'Who has ' + tpa + '? Tell ' + spa;
    } else if (op === 2) {
      p.info = spa + ' is at ' + sha;
    } else {
      p.info = 'ARP ' + opName;
    }
    p.details.push(section('Address Resolution Protocol', [
      ['Opcode', opName + ' (' + op + ')'],
      ['Sender MAC', sha],
      ['Sender IP', spa],
      ['Target MAC', tha + (tha === '00:00:00:00:00:00' ? '  (unknown, that is what we are asking for)' : '')],
      ['Target IP', tpa]
    ]));
  }

  /* ---------- layer 3 ---------- */

  function decodeIPv4(p, b, o) {
    var ihl = (b[o] & 0x0f) * 4;
    var totalLen = u16(b, o + 2), id = u16(b, o + 4);
    var flagsFrag = u16(b, o + 6), ttl = b[o + 8], proto = b[o + 9];
    var src = ip4(b, o + 12), dst = ip4(b, o + 16);
    var protoName = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' }[proto] || ('protocol ' + proto);
    p.src = src; p.dst = dst; p.proto = protoName; p.ttl = ttl;
    p.info = protoName;
    var flags = [];
    if (flagsFrag & 0x4000) flags.push("Don't Fragment");
    if (flagsFrag & 0x2000) flags.push('More Fragments');
    p.details.push(section('Internet Protocol version 4', [
      ['Source IP', src],
      ['Destination IP', dst + (dst === '255.255.255.255' ? '  (broadcast)' : '')],
      ['Protocol', protoName + ' (' + proto + ')'],
      ['Time to live (TTL)', String(ttl)],
      ['Total length', totalLen + ' bytes'],
      ['Identification', hex(id, 4)],
      ['Flags', flags.length ? flags.join(', ') : 'none']
    ]));
    var end = Math.min(b.length, o + totalLen);
    var next = o + ihl;
    if (proto === 1) decodeIcmp(p, b, next, end);
    else if (proto === 17) decodeUdp(p, b, next, end);
    else if (proto === 6) decodeTcp(p, b, next, end);
  }

  function decodeIcmp(p, b, o, end) {
    var type = b[o], code = b[o + 1];
    var names = { 0: 'Echo (ping) reply', 8: 'Echo (ping) request', 3: 'Destination unreachable', 11: 'Time exceeded' };
    var name = names[type] || ('ICMP type ' + type);
    var rows = [['Type', name + ' (' + type + ')'], ['Code', String(code)]];
    p.proto = 'ICMP';
    if (type === 0 || type === 8) {
      var id = u16(b, o + 4), seq = u16(b, o + 6);
      var dataLen = end - (o + 8);
      p.info = name + '  id=' + id + ', seq=' + seq + ', ttl=' + p.ttl;
      rows.push(['Identifier', id + ' (' + hex(id, 4) + ')  - same for every ping in one run of the ping command']);
      rows.push(['Sequence number', seq + '  - goes up by one for each ping sent']);
      rows.push(['Data', dataLen + ' bytes of filler that the reply must echo back unchanged']);
    } else {
      p.info = name;
    }
    p.details.push(section('Internet Control Message Protocol', rows));
  }

  /* ---------- layer 4: UDP ---------- */

  function decodeUdp(p, b, o, end) {
    var sport = u16(b, o), dport = u16(b, o + 2), len = u16(b, o + 4);
    var payload = o + 8, payloadLen = Math.max(0, Math.min(end, o + len) - payload);
    p.proto = 'UDP';
    p.sport = sport; p.dport = dport;
    p.info = sport + ' → ' + dport + '  Len=' + payloadLen;
    p.details.push(section('User Datagram Protocol', [
      ['Source port', String(sport)],
      ['Destination port', String(dport) + portHint(dport)],
      ['Length', len + ' bytes (8 byte header + ' + payloadLen + ' bytes of data)'],
      ['Reliability', 'none: no handshake, no acknowledgements, no retransmission']
    ]));
    if (payloadLen <= 0) return;
    if (sport === 53 || dport === 53) decodeDns(p, b, payload, payload + payloadLen);
    else if ((sport === 67 || sport === 68) && (dport === 67 || dport === 68)) decodeDhcp(p, b, payload, payload + payloadLen);
    else if (dport === 69 || tftpSessions[p.src + ':' + sport] || tftpSessions[p.dst + ':' + dport]) decodeTftp(p, b, payload, payload + payloadLen);
  }

  function decodeTftp(p, b, o, end) {
    var op = u16(b, o);
    var names = { 1: 'Read Request', 2: 'Write Request', 3: 'Data Packet', 4: 'Acknowledgement', 5: 'Error', 6: 'Option Acknowledgement' };
    var rows = [['Opcode', (names[op] || 'unknown') + ' (' + op + ')']];
    p.proto = 'TFTP';
    p.tftp = { op: op };
    if (op === 1 || op === 2) {
      var z1 = o + 2; while (z1 < end && b[z1] !== 0) z1++;
      var filename = ascii(b, o + 2, z1 - (o + 2));
      var z2 = z1 + 1; while (z2 < end && b[z2] !== 0) z2++;
      var mode = ascii(b, z1 + 1, z2 - (z1 + 1));
      tftpSessions[p.src + ':' + p.sport] = true;
      p.tftp.filename = filename; p.tftp.mode = mode;
      p.info = names[op] + ', File: ' + filename + ', Transfer type: ' + mode;
      rows.push(['File name', filename]);
      rows.push(['Mode', mode + (mode.toLowerCase() === 'octet' ? '  (raw bytes, exactly as stored)' : mode.toLowerCase() === 'netascii' ? '  (text, line endings converted)' : '')]);
      rows.push(['Sent to port', '69  - the only packet that uses the well-known port']);
    } else if (op === 3) {
      var block = u16(b, o + 2), dlen = end - (o + 4);
      p.tftp.block = block; p.tftp.data = b.slice(o + 4, end);
      p.info = 'Data Packet, Block: ' + block + (dlen < 512 ? ' (last)' : '');
      rows.push(['Block number', String(block)]);
      rows.push(['Data', dlen + ' bytes' + (dlen < 512 ? '  - shorter than 512, so this is the last block of the file' : '  - a full block; more will follow')]);
    } else if (op === 4) {
      var ablock = u16(b, o + 2);
      p.tftp.block = ablock;
      p.info = 'Acknowledgement, Block: ' + ablock;
      rows.push(['Block number', ablock + '  - "I received block ' + ablock + ', send the next one"']);
    } else if (op === 5) {
      var code = u16(b, o + 2), z = o + 4; while (z < end && b[z] !== 0) z++;
      var msg = ascii(b, o + 4, z - (o + 4));
      p.info = 'Error Code: ' + code + ', Message: ' + msg;
      rows.push(['Error code', String(code)], ['Message', msg]);
    } else if (op === 6) {
      p.info = 'Option Acknowledgement';
    } else {
      p.info = 'TFTP opcode ' + op;
    }
    p.details.push(section('Trivial File Transfer Protocol', rows));
  }

  function portHint(port) {
    var known = { 53: 'DNS', 67: 'DHCP server', 68: 'DHCP client', 69: 'TFTP', 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 123: 'NTP' };
    return known[port] ? '  (' + known[port] + ')' : '';
  }

  function dnsName(b, o, base, depth) {
    /* returns { name, next } handling compression pointers */
    depth = depth || 0;
    var labels = [], pos = o, next = null;
    while (pos < b.length) {
      var len = b[pos];
      if (len === 0) { pos++; break; }
      if ((len & 0xc0) === 0xc0) {
        var ptr = ((len & 0x3f) << 8) | b[pos + 1];
        if (next === null) next = pos + 2;
        if (depth > 10) break;
        var r = dnsName(b, base + ptr, base, depth + 1);
        labels.push(r.name);
        pos = null;
        break;
      }
      labels.push(ascii(b, pos + 1, len));
      pos += 1 + len;
    }
    return { name: labels.join('.'), next: next === null ? pos : next };
  }

  function decodeDns(p, b, o, end) {
    var id = u16(b, o), flags = u16(b, o + 2);
    var qd = u16(b, o + 4), an = u16(b, o + 6);
    var isResponse = !!(flags & 0x8000);
    var rcode = flags & 0x000f;
    var typeNames = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
    var pos = o + 12, questions = [], answers = [];
    for (var i = 0; i < qd && pos < end; i++) {
      var q = dnsName(b, pos, o); pos = q.next;
      var qtype = u16(b, pos); pos += 4;
      questions.push({ name: q.name, type: typeNames[qtype] || qtype });
    }
    for (var j = 0; j < an && pos < end; j++) {
      var a = dnsName(b, pos, o); pos = a.next;
      var atype = u16(b, pos), ttl = u32(b, pos + 4), rdlen = u16(b, pos + 8); pos += 10;
      var rdata = '';
      if (atype === 1 && rdlen === 4) rdata = ip4(b, pos);
      else if (atype === 5 || atype === 2 || atype === 12) rdata = dnsName(b, pos, o).name;
      else rdata = rdlen + ' bytes';
      pos += rdlen;
      answers.push({ name: a.name, type: typeNames[atype] || atype, ttl: ttl, data: rdata });
    }
    p.proto = 'DNS';
    p.dns = { id: id, response: isResponse, questions: questions, answers: answers };
    var qtext = questions.map(function (q) { return q.type + ' ' + q.name; }).join(', ');
    if (!isResponse) {
      p.info = 'Standard query ' + hex(id, 4) + ' ' + qtext;
    } else {
      var atext = answers.map(function (a) { return a.type + ' ' + a.data; }).join(', ');
      p.info = 'Standard query response ' + hex(id, 4) + ' ' + qtext + (atext ? ' → ' + atext : rcode ? ' (error ' + rcode + ')' : '');
    }
    var rows = [
      ['Transaction ID', hex(id, 4) + '  - the answer carries the same ID so the client can match it to the question'],
      ['Type', isResponse ? 'response' : 'query'],
      ['Question', qtext || '(none)']
    ];
    answers.forEach(function (a) { rows.push(['Answer', a.name + ' ' + a.type + ' ' + a.data + '  (TTL ' + a.ttl + ' s)']); });
    p.details.push(section('Domain Name System', rows));
  }

  function decodeDhcp(p, b, o, end) {
    var op = b[o], xid = u32(b, o + 4), secs = u16(b, o + 8), flags = u16(b, o + 10);
    var ciaddr = ip4(b, o + 12), yiaddr = ip4(b, o + 16), siaddr = ip4(b, o + 20);
    var chaddr = mac(b, o + 28);
    var msgNames = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
    var opts = {};
    var pos = o + 240; /* skip fixed header + magic cookie */
    if (u32(b, o + 236) !== 0x63825363) pos = end; /* no magic cookie: no options */
    while (pos < end) {
      var code = b[pos];
      if (code === 255) break;
      if (code === 0) { pos++; continue; }
      var len = b[pos + 1];
      opts[code] = b.subarray(pos + 2, pos + 2 + len);
      pos += 2 + len;
    }
    var msgType = opts[53] ? opts[53][0] : 0;
    var msgName = msgNames[msgType] || ('message type ' + msgType);
    p.proto = 'DHCP';
    p.info = 'DHCP ' + msgName + '  - Transaction ID ' + hex(xid, 8);
    var dnsList = [];
    if (opts[6]) for (var di = 0; di + 4 <= opts[6].length; di += 4) dnsList.push(ip4(opts[6], di));
    p.dhcp = {
      type: msgName, xid: xid, chaddr: chaddr, yiaddr: yiaddr, ciaddr: ciaddr,
      mask: opts[1] ? ip4(opts[1], 0) : null, router: opts[3] ? ip4(opts[3], 0) : null,
      dns: dnsList, serverId: opts[54] ? ip4(opts[54], 0) : null, lease: opts[51] ? u32(opts[51], 0) : null
    };
    var rows = [
      ['Message type', msgName + ' (option 53 = ' + msgType + ')'],
      ['Transaction ID', hex(xid, 8) + '  - stays the same for all four DORA messages'],
      ['Direction', op === 1 ? 'client → server (BOOTP request)' : 'server → client (BOOTP reply)'],
      ['Client MAC', chaddr],
      ['Client IP (ciaddr)', ciaddr + (ciaddr === '0.0.0.0' ? '  (client has no address yet)' : '')],
      ['Your IP (yiaddr)', yiaddr + (yiaddr === '0.0.0.0' ? '' : '  (the address being handed out)')]
    ];
    if (siaddr !== '0.0.0.0') rows.push(['Server IP (siaddr)', siaddr]);
    if (secs) rows.push(['Seconds elapsed', String(secs)]);
    rows.push(['Broadcast flag', (flags & 0x8000) ? 'set (please reply by broadcast)' : 'not set']);
    if (opts[50]) rows.push(['Requested IP (option 50)', ip4(opts[50], 0)]);
    if (opts[54]) rows.push(['DHCP server (option 54)', ip4(opts[54], 0)]);
    if (opts[51]) rows.push(['Lease time (option 51)', u32(opts[51], 0) + ' seconds (' + (u32(opts[51], 0) / 3600) + ' hours)']);
    if (opts[1]) rows.push(['Subnet mask (option 1)', ip4(opts[1], 0)]);
    if (opts[3]) rows.push(['Router / gateway (option 3)', ip4(opts[3], 0)]);
    if (opts[6]) {
      var dns = [];
      for (var i = 0; i + 4 <= opts[6].length; i += 4) dns.push(ip4(opts[6], i));
      rows.push(['DNS servers (option 6)', dns.join(', ')]);
    }
    if (opts[15]) rows.push(['Domain name (option 15)', ascii(opts[15], 0, opts[15].length)]);
    if (opts[61]) rows.push(['Client identifier (option 61)', opts[61][0] === 1 ? mac(opts[61], 1) : opts[61].length + ' bytes']);
    if (opts[55]) {
      var names = { 1: 'subnet mask', 3: 'router', 6: 'DNS', 15: 'domain name', 42: 'NTP', 119: 'search list' };
      var want = [];
      for (var k = 0; k < opts[55].length; k++) want.push(names[opts[55][k]] || opts[55][k]);
      rows.push(['Parameters requested (option 55)', want.join(', ')]);
    }
    p.details.push(section('Dynamic Host Configuration Protocol', rows));
  }

  /* ---------- layer 4: TCP ---------- */

  function decodeTcp(p, b, o, end) {
    var sport = u16(b, o), dport = u16(b, o + 2);
    var seq = u32(b, o + 4), ack = u32(b, o + 8);
    var dataOff = (b[o + 12] >> 4) * 4, flagBits = b[o + 13], win = u16(b, o + 14);
    var payload = o + dataOff, payloadLen = Math.max(0, end - payload);
    var names = [];
    if (flagBits & 0x02) names.push('SYN');
    if (flagBits & 0x01) names.push('FIN');
    if (flagBits & 0x04) names.push('RST');
    if (flagBits & 0x08) names.push('PSH');
    if (flagBits & 0x10) names.push('ACK');
    if (flagBits & 0x20) names.push('URG');
    var order = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'];
    names.sort(function (a, c) { return order.indexOf(a) - order.indexOf(c); });

    /* options (only the ones students meet in a handshake) */
    var optRows = [], mss = null, wscale = null, sack = false;
    var pos = o + 20;
    while (pos < o + dataOff) {
      var kind = b[pos];
      if (kind === 0) break;
      if (kind === 1) { pos++; continue; }
      var len = b[pos + 1];
      if (kind === 2) mss = u16(b, pos + 2);
      else if (kind === 3) wscale = b[pos + 2];
      else if (kind === 4) sack = true;
      pos += len || 2;
    }
    if (mss !== null) optRows.push(['Max segment size (MSS)', mss + ' bytes  - biggest chunk of data I can accept per packet']);
    if (wscale !== null) optRows.push(['Window scale', 'shift ' + wscale + '  (multiply the window by ' + Math.pow(2, wscale) + ')']);
    if (sack) optRows.push(['SACK permitted', 'yes  - selective acknowledgement allowed']);

    p.proto = 'TCP';
    p.sport = sport; p.dport = dport;
    p.tcp = { seq: seq, ack: ack, flags: names, syn: !!(flagBits & 0x02), hasAck: !!(flagBits & 0x10), win: win, len: payloadLen, mss: mss, wscale: wscale };
    p.tcpSection = section('Transmission Control Protocol', [
      ['Source port', String(sport) + portHint(sport)],
      ['Destination port', String(dport) + portHint(dport)],
      ['Flags', '[' + names.join(', ') + ']'],
      ['Sequence number', '(filled in below)'],
      ['Acknowledgement number', '(filled in below)'],
      ['Window size', win + (wscale !== null ? '  - bytes I can accept right now' : '  - multiply by the scale factor agreed in the SYN to get real bytes')],
      ['Payload', payloadLen + ' bytes']
    ].concat(optRows));
    p.details.push(p.tcpSection);

    if (payloadLen > 0 && (sport === 80 || dport === 80)) decodeHttp(p, b, payload, end);
    else if (sport === 443 || dport === 443) {
      /* keep the raw bytes: tls.js reassembles the stream and decrypts it */
      p.payload = b.slice(payload, end);
      if (payloadLen > 0) decodeTls(p, b, payload, end);
    }
  }

  function decodeHttp(p, b, o, end) {
    var n = Math.min(end - o, 512);
    if (!isPrintable(b, o, Math.min(n, 64))) {
      p.httpInfo = 'Continuation of HTTP data (' + (end - o) + ' bytes, not text)';
      return;
    }
    var text = ascii(b, o, n);
    var firstLine = text.split(/\r?\n/)[0];
    var isRequest = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) /.test(firstLine);
    var isResponse = /^HTTP\/\d/.test(firstLine);
    if (!isRequest && !isResponse) {
      p.httpInfo = 'Continuation of HTTP data (' + (end - o) + ' bytes)';
      p.proto = 'HTTP';
      p.details.push(section('Hypertext Transfer Protocol', [['Body', 'more of the response body, ' + (end - o) + ' bytes; first characters: ' + JSON.stringify(text.slice(0, 60))]]));
      return;
    }
    var headerEnd = text.indexOf('\r\n\r\n');
    var headerText = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
    var lines = headerText.split(/\r?\n/);
    var rows = [[isRequest ? 'Request line' : 'Status line', lines[0]]];
    var ctype = '';
    for (var i = 1; i < lines.length && i < 20; i++) {
      var idx = lines[i].indexOf(':');
      if (idx > 0) {
        var name = lines[i].slice(0, idx), val = lines[i].slice(idx + 1).trim();
        rows.push([name, val]);
        if (name.toLowerCase() === 'content-type') ctype = val;
      }
    }
    if (headerEnd >= 0) {
      var bodyStart = o + headerEnd + 4;
      var bodyBytes = end - bodyStart;
      if (bodyBytes > 0) rows.push(['Body (this packet)', bodyBytes + ' bytes; begins: ' + JSON.stringify(ascii(b, bodyStart, Math.min(bodyBytes, 60)))]);
    }
    p.proto = 'HTTP';
    p.httpInfo = lines[0] + (ctype ? '  (' + ctype.split(';')[0] + ')' : '');
    p.details.push(section('Hypertext Transfer Protocol', rows));
  }

  /* ---------- TLS (what HTTPS looks like on the wire) ---------- */

  var CIPHERS = {
    0x1301: 'TLS_AES_128_GCM_SHA256 (TLS 1.3)', 0x1302: 'TLS_AES_256_GCM_SHA384 (TLS 1.3)', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)',
    0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256', 0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256', 0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384', 0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
    0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305', 0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305', 0xc013: 'ECDHE-RSA-AES128-SHA', 0xc014: 'ECDHE-RSA-AES256-SHA',
    0x009c: 'RSA-AES128-GCM-SHA256 (RSA key exchange, no forward secrecy)', 0x009d: 'RSA-AES256-GCM-SHA384 (RSA key exchange, no forward secrecy)',
    0x002f: 'RSA-AES128-SHA (RSA key exchange)', 0x0035: 'RSA-AES256-SHA (RSA key exchange)', 0x00ff: 'EMPTY_RENEGOTIATION_INFO'
  };
  function cipherName(c) {
    if ((c & 0x0f0f) === 0x0a0a) return 'GREASE ' + hex(c, 4) + ' (random filler the browser adds on purpose)';
    return CIPHERS[c] || hex(c, 4);
  }
  var TLS_VERSIONS = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
  function tlsVersion(v) { return (v & 0x0f0f) === 0x0a0a ? 'GREASE' : (TLS_VERSIONS[v] || hex(v, 4)); }
  var HANDSHAKE = { 0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange',
    13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
  var GROUPS = { 0x001d: 'x25519', 0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x11ec: 'X25519MLKEM768 (post-quantum hybrid)', 0x6399: 'X25519Kyber768' };
  function hexBytes(b, o, n) { var s = ''; for (var i = 0; i < n; i++) s += b[o + i].toString(16).padStart(2, '0'); return s; }

  /* Continuation bookkeeping: a record that did not fit in one TCP segment
   * spills into the next segments of the same direction. */
  var tlsPending = {}, tlsEncrypted = {};

  function decodeTls(p, b, o, end) {
    var key = p.src + ':' + p.sport + '>' + p.dst + ':' + p.dport;
    var names = [], rows = [], recs = [], pos = o;
    var pend = tlsPending[key] || 0;
    if (pend > 0) {
      var take = Math.min(pend, end - o);
      tlsPending[key] = pend - take;
      names.push('Continuation Data');
      rows.push(['Continuation', take + ' more bytes of a record that started in an earlier packet']);
      pos = o + take;
    }
    while (pos + 5 <= end) {
      var type = b[pos], ver = u16(b, pos + 1), len = u16(b, pos + 3);
      if (type < 20 || type > 24) { rows.push(['Unrecognised bytes', (end - pos) + ' bytes that are not a TLS record header']); break; }
      var bodyStart = pos + 5, avail = Math.min(len, end - bodyStart), complete = avail === len;
      var rec = { type: type, version: ver, len: len, offset: pos - o, complete: complete };
      var label;
      if (type === 20) { label = 'Change Cipher Spec'; tlsEncrypted[key] = true; rows.push(['Change Cipher Spec', 'from here on, everything this side sends is encrypted']); }
      else if (type === 21) { label = 'Alert'; rows.push(['Alert', 'encrypted alert, ' + len + ' bytes (usually close_notify: "I am done")']); }
      else if (type === 23) { label = 'Application Data'; rows.push(['Application Data', len + ' bytes of ciphertext' + (complete ? '' : ' (continues in the next packet)') + ' - the HTTP request or response, unreadable without the keys']); }
      else if (type === 22 && tlsEncrypted[key]) { label = 'Encrypted Handshake Message'; rows.push(['Encrypted Handshake Message', len + ' bytes: the Finished message, already scrambled with the new session keys']); }
      else if (type === 22) { label = decodeHandshake(p, b, bodyStart, bodyStart + avail, complete, rec, rows); }
      else label = 'Heartbeat';
      names.push(label);
      recs.push(rec);
      if (!complete) { tlsPending[key] = len - avail; break; }
      pos = bodyStart + len;
    }
    p.proto = p.tlsVersionSeen || 'TLS';
    p.tls = { records: recs, info: names.join(', ') };
    p.tlsInfo = names.join(', ');
    p.details.push(section('Transport Layer Security', [['Records in this packet', names.join(', ')]].concat(rows)));
  }

  function decodeHandshake(p, b, o, end, complete, rec, rows) {
    var ht = b[o], hlen, body, name, labels = [];
    rec.hsType = ht;
    while (o + 4 <= end) {
      ht = b[o]; hlen = (b[o + 1] << 16) | u16(b, o + 2); body = o + 4;
      name = HANDSHAKE[ht] || ('Handshake type ' + ht);
      labels.push(name);
      var bend = Math.min(body + hlen, end);
      if (ht === 1) decodeClientHello(p, b, body, bend, rows);
      else if (ht === 2) decodeServerHello(p, b, body, bend, rows);
      else if (ht === 11) rows.push(['Certificate', hlen + ' bytes: the server\'s certificate chain, sent in the clear. It holds the public key and the name the certificate was issued for.']);
      else if (ht === 12) rows.push(['Server Key Exchange', hlen + ' bytes: the server\'s ephemeral Diffie-Hellman share, signed with the certificate\'s key']);
      else if (ht === 14) rows.push(['Server Hello Done', 'the server has said everything it needs to; now it is the client\'s move']);
      else if (ht === 16) rows.push(['Client Key Exchange', hlen + ' bytes: the pre-master secret, encrypted with the server\'s PUBLIC key. Only the PRIVATE key can open it.']);
      else if (ht === 4) rows.push(['New Session Ticket', hlen + ' bytes']);
      else rows.push([name, hlen + ' bytes']);
      if (!complete && body + hlen > end) { labels[labels.length - 1] += ' (continues in the next packet)'; break; }
      o = body + hlen;
    }
    return labels.join(', ');
  }

  function decodeClientHello(p, b, o, end, rows) {
    var ver = u16(b, o), random = hexBytes(b, o + 2, 32), sidLen = b[o + 34], pos = o + 35 + sidLen;
    var csLen = u16(b, pos), suites = []; pos += 2;
    for (var i = 0; i < csLen; i += 2) suites.push(u16(b, pos + i));
    pos += csLen;
    var compLen = b[pos]; pos += 1 + compLen;
    var sni = null, versions = [], groups = [], alpn = [];
    if (pos + 2 <= end) {
      var extEnd = pos + 2 + u16(b, pos); pos += 2;
      while (pos + 4 <= extEnd) {
        var et = u16(b, pos), el = u16(b, pos + 2), ed = pos + 4;
        if (et === 0 && el > 5) sni = ascii(b, ed + 5, u16(b, ed + 3));
        else if (et === 43) { for (var j = 1; j < el; j += 2) versions.push(tlsVersion(u16(b, ed + j))); }
        else if (et === 10) { for (var k = 2; k < el; k += 2) { var g = u16(b, ed + k); groups.push((g & 0x0f0f) === 0x0a0a ? 'GREASE' : (GROUPS[g] || hex(g, 4))); } }
        else if (et === 16) { var q = ed + 2; while (q < ed + el) { var al = b[q]; alpn.push(ascii(b, q + 1, al)); q += 1 + al; } }
        pos = ed + el;
      }
    }
    p.tlsClientRandom = random;
    p.tlsVersionSeen = 'TLSv1.2';   /* the record layer says 1.2 even when 1.3 is offered; the Server Hello settles it */
    rows.push(['Client Hello', 'the browser opens: "here is what I can do, you choose"']);
    rows.push(['Legacy version', tlsVersion(ver) + ' in the header for compatibility' + (versions.length ? '; real offer in supported_versions: ' + versions.join(', ') : '')]);
    rows.push(['Client random', random.slice(0, 16) + '... (32 random bytes; the key log file is indexed by this value)']);
    rows.push(['Session ID', sidLen ? sidLen + ' bytes: ' + hexBytes(b, o + 35, Math.min(sidLen, 8)) + '...' : 'none']);
    rows.push(['Cipher suites offered (' + suites.length + ')', suites.map(cipherName).join('\n')]);
    if (sni) rows.push(['Server name (SNI)', sni + ' - sent in the clear, so a sniffer always sees WHICH site you visit']);
    else rows.push(['Server name (SNI)', 'none: the site was addressed by IP, not by name']);
    if (groups.length) rows.push(['Key exchange groups', groups.join(', ')]);
    if (alpn.length) rows.push(['ALPN (what to speak after TLS)', alpn.join(', ')]);
  }

  function decodeServerHello(p, b, o, end, rows) {
    var ver = u16(b, o), random = hexBytes(b, o + 2, 32), sidLen = b[o + 34], pos = o + 35 + sidLen;
    var cipher = u16(b, pos); pos += 3;   /* cipher + compression */
    var chosen = null, group = null;
    if (pos + 2 <= end) {
      var extEnd = pos + 2 + u16(b, pos); pos += 2;
      while (pos + 4 <= extEnd) {
        var et = u16(b, pos), el = u16(b, pos + 2), ed = pos + 4;
        if (et === 43) chosen = tlsVersion(u16(b, ed));
        else if (et === 51) { var g = u16(b, ed); group = GROUPS[g] || hex(g, 4); }
        pos = ed + el;
      }
    }
    var v = chosen || tlsVersion(ver);
    p.tlsServerRandom = random; p.tlsCipher = cipher; p.tlsNegotiated = v;
    p.tlsVersionSeen = v === 'TLS 1.3' ? 'TLSv1.3' : 'TLSv1.2';
    rows.push(['Server Hello', 'the server chooses: "we will use ' + v + ' with ' + cipherName(cipher) + '"']);
    rows.push(['Version', v]);
    rows.push(['Server random', random.slice(0, 16) + '... (32 random bytes)']);
    rows.push(['Session ID', sidLen ? sidLen + ' bytes' : 'none']);
    rows.push(['Cipher suite', cipherName(cipher)]);
    if (group) rows.push(['Key share', group + ' - the server\'s half of an ephemeral Diffie-Hellman exchange (forward secrecy)']);
  }

  /* Wireshark shows sequence numbers relative to the first one seen in each
   * direction, which is far easier to read. Do the same here. */
  function makeTcpSeqRelative(packets) {
    var isn = {}, tlsVer = {};
    packets.forEach(function (p) {
      if (p.tlsNegotiated) tlsVer[[p.src + ':' + p.sport, p.dst + ':' + p.dport].sort().join('|')] = p.tlsVersionSeen;
    });
    packets.forEach(function (p) {
      if (!p.tcp) return;
      var fwd = p.src + ':' + p.sport + '>' + p.dst + ':' + p.dport;
      var rev = p.dst + ':' + p.dport + '>' + p.src + ':' + p.sport;
      if (isn[fwd] === undefined) isn[fwd] = p.tcp.seq;
      var relSeq = (p.tcp.seq - isn[fwd]) >>> 0;
      var relAck = p.tcp.hasAck && isn[rev] !== undefined ? (p.tcp.ack - isn[rev]) >>> 0 : null;
      var t = p.tcp;
      var parts = [p.sport + ' → ' + p.dport, '[' + t.flags.join(', ') + ']', 'Seq=' + relSeq];
      if (relAck !== null) parts.push('Ack=' + relAck);
      parts.push('Win=' + t.win, 'Len=' + t.len);
      if (t.syn && t.mss) parts.push('MSS=' + t.mss);
      if (p.tls) {
        var conn = [p.src + ':' + p.sport, p.dst + ':' + p.dport].sort().join('|');
        if (tlsVer[conn]) p.proto = tlsVer[conn];
      }
      p.info = p.httpInfo ? p.httpInfo : p.tlsInfo ? p.tlsInfo : parts.join(' ');
      /* fill the placeholders in the detail rows */
      p.tcpSection.rows.forEach(function (r) {
        if (r[0] === 'Sequence number') r[1] = relSeq + ' (relative)   raw: ' + t.seq;
        if (r[0] === 'Acknowledgement number') r[1] = relAck === null ? (t.hasAck ? String(t.ack) : 'not used (ACK flag off)') : relAck + ' (relative)   raw: ' + t.ack;
      });
      if (p.httpInfo || p.tlsInfo) p.tcpSection.rows.push(['TCP summary', parts.join(' ')]);
    });
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { parsePcap: parsePcap };
  else root.parsePcap = parsePcap;
})(typeof window !== 'undefined' ? window : this);
