/* app.js - wires the left column to the right column. No frameworks. */
(function () {
  'use strict';

  var nav = document.getElementById('nav');
  var main = document.getElementById('main');
  var pcapCache = {}, textCache = {};

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  /* ---------- expanding site menu (the whole left rail is the button) ---------- */

  function buildMenu() {
    var panel = document.getElementById('sitemenu'), btn = document.getElementById('menu-btn');
    if (!panel || !btn || !SITE.menu) return;
    panel.innerHTML = '<div class="sitemenu-title">Sites</div>' + SITE.menu.map(function (m) {
      if (!m.href) return '<span class="menu-item soon"><span>' + esc(m.label) + '</span><small>coming soon</small></span>';
      return '<a class="menu-item' + (m.current ? ' current' : '') + '" href="' + esc(m.href) + '"' + (m.current ? ' aria-current="page"' : '') + '>' + esc(m.label) + (m.current ? '<small>you are here</small>' : '') + '</a>';
    }).join('') + '<div class="sitemenu-foot">Click anywhere else, or press Escape, to close.</div>';

    var leaveTimer = null;
    function setOpen(open) {
      panel.classList.toggle('open', open);
      btn.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Close site menu' : 'Open site menu');
      if (leaveTimer) { clearTimeout(leaveTimer); leaveTimer = null; }
    }
    function isOpen() { return panel.classList.contains('open'); }

    btn.addEventListener('click', function (e) { e.stopPropagation(); setOpen(!isOpen()); });
    panel.addEventListener('click', function (e) {
      e.stopPropagation();
      if (e.target.closest('a.menu-item')) setOpen(false);
    });
    document.addEventListener('click', function () { if (isOpen()) setOpen(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && isOpen()) { setOpen(false); btn.focus(); } });
    panel.addEventListener('mouseleave', function () { if (isOpen()) leaveTimer = setTimeout(function () { setOpen(false); }, 1200); });
    panel.addEventListener('mouseenter', function () { if (leaveTimer) { clearTimeout(leaveTimer); leaveTimer = null; } });
    panel.addEventListener('focusout', function (e) { if (!panel.contains(e.relatedTarget) && e.relatedTarget !== btn) setOpen(false); });
  }

  /* ---------- left column ---------- */

  function buildNav() {
    LESSONS.forEach(function (l, i) {
      var b = document.createElement('button');
      b.className = 'row';
      b.type = 'button';
      b.dataset.id = l.id;
      b.innerHTML =
        '<span class="num">' + (i + 1) + '</span>' +
        '<span class="text"><span class="title">' + esc(l.title) + '</span>' +
        '<span class="sub">' + esc(l.subtitle) + '</span></span>';
      b.addEventListener('click', function () { location.hash = l.id; });
      nav.appendChild(b);
    });
  }

  function setActive(id) {
    Array.prototype.forEach.call(nav.querySelectorAll('.row'), function (b) {
      b.classList.toggle('active', b.dataset.id === id);
    });
  }

  /* ---------- sequence diagram ---------- */

  function diagram(lesson) {
    var actors = lesson.actors, steps = lesson.steps;
    var colW = 500, left = 150, top = 70, rowH = 34;
    var width = left * 2 + colW * (actors.length - 1);
    var height = top + rowH * steps.length + 30;
    var xs = actors.map(function (a, i) { return left + colW * i; });
    var out = [];
    out.push('<svg class="seq" viewBox="0 0 ' + width + ' ' + height + '" style="max-width:' + width + 'px" role="img" aria-label="Sequence diagram">');
    var head = '<path d="M0 0 L10 5 L0 10 z"/>';
    function marker(id) { return '<marker id="' + id + '" class="' + id + '" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">' + head + '</marker>'; }
    out.push('<defs>' + marker('arrow') + marker('arrow-bcast') + marker('arrow-dashed') + '</defs>');
    actors.forEach(function (a, i) {
      out.push('<line class="life" x1="' + xs[i] + '" y1="' + (top - 10) + '" x2="' + xs[i] + '" y2="' + (height - 10) + '"/>');
      out.push('<text class="actor" x="' + xs[i] + '" y="24" text-anchor="middle">' + esc(a.name) + '</text>');
      out.push('<text class="addr" x="' + xs[i] + '" y="42" text-anchor="middle">' + esc(a.addr) + '</text>');
    });
    steps.forEach(function (s, i) {
      var y = top + rowH * i + 12;
      var x1 = xs[s.from], x2 = xs[s.to], cls = 'msg' + (s.dashed ? ' dashed' : '');
      out.push('<line class="' + cls + '" x1="' + x1 + '" y1="' + y + '" x2="' + x2 + '" y2="' + y + '" marker-end="url(#' + (s.dashed ? 'arrow-dashed' : 'arrow') + ')"/>');
      out.push('<text class="label" x="' + ((x1 + x2) / 2) + '" y="' + (y - 6) + '" text-anchor="middle">' + esc(s.label) + '</text>');
      out.push('<text class="stepno" x="18" y="' + (y + 4) + '" text-anchor="middle">' + (i + 1) + '</text>');
    });
    out.push('</svg>');
    return out.join('');
  }

  /* ---------- looping packet-assembly animation ---------- */

  function assemblyHtml(key, a) {
    var h = ['<div class="asm" data-anim="' + key + '" aria-label="Animation: ' + esc(a.label) + '">'];
    h.push('<div class="asm-caption"><span class="asm-dots">' + a.stages.map(function (s, i) { return '<i data-i="' + i + '"></i>'; }).join('') + '</span><span class="asm-text"></span></div>');
    h.push('<div class="asm-bar">');
    a.segments.forEach(function (g) {
      h.push('<div class="seg seg-' + (g.color || g.id) + (g.ghost ? ' seg-ghost' : '') + '" data-seg="' + g.id + '" style="--w:' + g.width + '%">' +
        '<div class="seg-name">' + esc(g.name) + '</div>' +
        '<div class="seg-bytes">' + g.bytes + ' bytes</div>' +
        '<div class="seg-fields">' + g.fields.map(function (f) { return '<span>' + esc(f) + '</span>'; }).join('') + '</div></div>');
    });
    h.push('</div>');
    h.push('<div class="asm-total"><span class="asm-total-label">Frame so far</span> <b class="asm-bytes">0</b> bytes</div>');
    h.push('</div>');
    return h.join('');
  }

  /* Frame 49 of the login capture: 14 + 20 + 32 + 5 + 8 + 742 + 16 = 837 bytes. */
  var ANIMATIONS = {
    'tls-record': {
      label: 'how the login request is encrypted and wrapped, layer by layer',
      segments: [
        { id: 'eth',    name: 'Ethernet header', bytes: 14,  width: 13, fields: ['dst 36:cc:4c:8e:63:0b', 'src aa:31:a6:04:60:79', 'type 0x0800 = IPv4'] },
        { id: 'ip',     name: 'IP header',       bytes: 20,  width: 15, fields: ['from 192.168.110.50', 'to 192.168.110.1', 'protocol 6 = TCP'] },
        { id: 'tcp',    name: 'TCP header',      bytes: 32,  width: 17, fields: ['src port 46516', 'dst port 443 (HTTPS)', 'flags [PSH, ACK]', 'seq 2243, timestamps'] },
        { id: 'rec',    name: 'TLS record header', bytes: 5, width: 11, color: 'udp', fields: ['type 23 = Application Data', 'version 0x0303', 'length 766'] },
        { id: 'nonce',  name: 'Nonce',           bytes: 8,   width: 10, color: 'icmp', fields: ['8 bytes', 'fresh each', 'record'] },
        { id: 'plain',  name: 'HTTP request, plain', bytes: 742, width: 30, color: 'data', fields: ['GET /action_page.php', '?name=Tux&pwd=Penguin2026!', 'Host: 192.168.110.1', 'User-Agent: ... Chrome/152', 'Accept: text/html ...'] },
        { id: 'cipher', name: 'Ciphertext',      bytes: 742, width: 20, color: 'tcp', fields: ['AES-128-GCM', 'same length as the plain text', 'e9 7f 03 c4 5a ...', 'no readable bytes'] },
        { id: 'tag',    name: 'Auth tag',        bytes: 16,  width: 10, color: 'icmp', fields: ['16 bytes', 'tamper', 'check'] }
      ],
      stages: [
        { on: ['plain'],                                        hold: 3600, caption: 'The browser has a normal HTTP request to send: 742 bytes, starting GET /action_page.php?name=Tux&pwd=Penguin2026! On the Protocols site this is where the story ended and the request went on the wire as is.' },
        { on: ['nonce', 'cipher', 'tag'],                       hold: 4200, caption: 'AES-GCM scrambles it with the session key agreed in the handshake. The ciphertext is exactly as long as the plaintext, 742 bytes, but none of it is readable. An 8-byte nonce (a number used once) goes in front so that identical requests never encrypt the same way, and a 16-byte authentication tag goes at the end: change one bit in transit and the receiver throws the whole record away.' },
        { on: ['rec', 'nonce', 'cipher', 'tag'],                hold: 3800, caption: 'TLS puts a 5-byte record header in front: type 23 (Application Data), version 3.3 (TLS 1.2), length 766. The header itself is not encrypted, so a sniffer can tell that data was sent and how much, just not what.' },
        { on: ['tcp', 'rec', 'nonce', 'cipher', 'tag'],         hold: 3600, caption: 'TCP adds its header: from port 46516 to port 443. Ports, sequence numbers, flags and window are all in the clear. Encryption starts above TCP, never below it.' },
        { on: ['ip', 'tcp', 'rec', 'nonce', 'cipher', 'tag'],   hold: 3400, caption: 'IP adds 192.168.110.50 to 192.168.110.1. Who is talking to whom is never a secret on a network; only what they say can be.' },
        { on: ['eth', 'ip', 'tcp', 'rec', 'nonce', 'cipher', 'tag'], hold: 3800, caption: 'Ethernet adds the MAC addresses. 837 bytes on the wire: 66 bytes of readable headers and 771 bytes of TLS. This is frame 49 in the capture below.' },
        { on: ['eth', 'ip', 'tcp', 'rec', 'nonce', 'cipher', 'tag'], done: true, hold: 3000, caption: 'Sent. The server strips the headers, checks the tag, decrypts with the same session key, reads the password, and answers with a 200 OK built exactly the same way in the other direction.' }
      ]
    }
  };

  var animTimers = [];
  function stopAnimations() { animTimers.forEach(clearTimeout); animTimers = []; }

  function startAnimations() {
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    Array.prototype.forEach.call(main.querySelectorAll('[data-anim]'), function (el) {
      var a = ANIMATIONS[el.dataset.anim];
      if (!a) return;
      var segs = {}; Array.prototype.forEach.call(el.querySelectorAll('.seg'), function (s) { segs[s.dataset.seg] = s; });
      var text = el.querySelector('.asm-text'), dots = el.querySelectorAll('.asm-dots i'), bytesEl = el.querySelector('.asm-bytes');
      function apply(i) {
        var st = a.stages[i], total = 0;
        a.segments.forEach(function (g) {
          var on = st.on.indexOf(g.id) >= 0;
          segs[g.id].classList.toggle('on', on);
          if (on) total += g.bytes;
        });
        el.classList.toggle('done', !!st.done);
        text.textContent = st.caption;
        bytesEl.textContent = total;
        Array.prototype.forEach.call(dots, function (d, j) { d.classList.toggle('on', j === i); });
      }
      if (reduce) { apply(a.stages.length - 1); return; }
      var i = 0;
      function step() {
        apply(i);
        var hold = a.stages[i].hold;
        i = (i + 1) % a.stages.length;
        animTimers.push(setTimeout(step, hold));
      }
      step();
    });
  }

  /* ---------- right column ---------- */

  function renderWelcome() {
    main.innerHTML =
      '<article class="welcome">' +
      '<h1>Encryption and Protocols</h1>' +
      '<p class="lead">What HTTPS looks like on the wire, why a sniffer cannot read it, and how you can, when you hold the keys.</p>' +
      '<h2>How to use this page</h2>' +
      '<ol>' +
      '<li>Work through the rows on the left in order. Row 1 shows a real HTTPS login as a sniffer sees it; row 4 decrypts it; row 5 does the same with your own browser and a real website.</li>' +
      '<li>Every row with a capture has a Wireshark-style packet table at the bottom. Click a packet to open it layer by layer.</li>' +
      '<li>The download buttons give you the same capture and key files, so you can repeat everything in Wireshark.</li>' +
      '</ol>' +
      '<div class="banner warn"><b>This lab is deliberately insecure.</b> The server hands out its private key, uses an RSA key exchange with no forward secrecy, and logs every session secret. That is the opposite of what a real server should do, and it is the only way to see what the keys actually unlock.</div>' +
      '<h2>The two captures</h2>' +
      '<div class="table-wrap"><table class="lab"><tr><th>File</th><th>What happened</th><th>TLS</th><th>Keys that open it</th></tr>' +
      '<tr><td><code>' + esc(FILES.login) + '</code></td><td>Chrome logged in to a lab web server on ' + esc(SITE.labName) + ' (' + esc(SITE.labNetwork) + '): the login page, a missing favicon, and the form submission with the password. 69 packets, 4 connections.</td><td>TLS 1.2, RSA-AES128-GCM-SHA256</td><td><code>keylog.txt</code> (server), <code>chrome-keylog.txt</code> (browser), or <code>server.key</code></td></tr>' +
      '<tr><td><code>' + esc(FILES.pages) + '</code></td><td>Chromium loaded the Protocols site from GitHub Pages: DNS, then nine connections fetching the page, its scripts and three pcap files. 182 packets.</td><td>TLS 1.3, TLS_AES_128_GCM_SHA256, x25519</td><td><code>github-pages-keylog.txt</code> (browser) only. No private key can open this one.</td></tr>' +
      '</table></div>' +
      '<h2>Run the live server yourself</h2>' +
      '<p class="hint">Both captures on this site are recordings. The server behind the first one is published on Docker Hub, so you can make your own capture instead of studying mine. It listens on port 443 inside the container; this maps it to port ' + SITE.port + ' on your machine:</p>' +
      '<pre class="cmd">docker run -d --name https-demo -p ' + SITE.port + ':443 ' + esc(SITE.image) + '</pre>' +
      '<p class="hint">Then open <a href="https://localhost:' + SITE.port + '/">https://localhost:' + SITE.port + '/</a> with Wireshark capturing on the loopback interface. Row 4 has the full steps. The container makes a new private key every time it starts, so its files will not open the recording here, only your own capture. Stop it with <code>docker rm -f https-demo</code>.</p>' +
      '<h2>Reading the packet table</h2>' +
      '<ul>' +
      '<li><b>Protocol</b> says TLSv1.2 or TLSv1.3 once the handshake has settled the version. Application Data is the encrypted HTTP.</li>' +
      '<li><b>Info</b> lists the TLS records in the packet, the way Wireshark does: Client Hello, Server Hello, Certificate, Change Cipher Spec, Application Data, Alert.</li>' +
      '<li><b>Continuation Data</b> means a record that started in an earlier packet is still going. One TLS record can be up to 16 KB and span many packets.</li>' +
      '<li>Open a Client Hello to see the cipher suites the browser offered, and a Server Hello to see which one the server picked.</li>' +
      '</ul>' +
      '</article>';
  }

  function sectionHtml(s) {
    var h = ['<section><h2>' + esc(s.h) + '</h2>'];
    (s.p || []).forEach(function (p) { h.push('<p>' + p + '</p>'); });
    if (s.anim && ANIMATIONS[s.anim]) h.push(assemblyHtml(s.anim, ANIMATIONS[s.anim]));
    if (s.steps) { h.push('<ol class="steps">'); s.steps.forEach(function (t) { h.push('<li>' + t + '</li>'); }); h.push('</ol>'); }
    if (s.keylog) h.push('<pre class="keyfile" data-src="' + esc(s.keylog) + '"' + (s.keylogLines ? ' data-lines="' + s.keylogLines + '"' : '') + '>Loading ' + esc(s.keylog) + ' ...</pre>');
    if (s.table) {
      h.push('<div class="table-wrap"><table class="lab compare">');
      s.table.forEach(function (row, i) { h.push('<tr>' + row.map(function (c, j) { return (i === 0 || j === 0 ? '<th>' : '<td>') + c + (i === 0 || j === 0 ? '</th>' : '</td>'); }).join('') + '</tr>'); });
      h.push('</table></div>');
    }
    (s.after || []).forEach(function (p) { h.push('<p>' + p + '</p>'); });
    if (s.files) {
      h.push('<div class="files">');
      s.files.forEach(function (f) { h.push('<a class="dl" href="' + esc(f.href) + '" download>' + esc(f.label) + '</a>' + (f.note ? '<span class="file-note">' + esc(f.note) + '</span>' : '')); });
      h.push('</div>');
    }
    if (s.decrypt) h.push('<div class="decrypt" data-file="' + esc(s.decrypt.file) + '" data-keylog="' + esc(s.decrypt.keylog) + '" data-highlight="' + esc(s.decrypt.highlight || '') + '"><p class="loading">Decrypting the capture in your browser...</p></div>');
    h.push('</section>');
    return h.join('');
  }

  function renderLesson(lesson, index) {
    var h = [];
    h.push('<article class="lesson" id="lesson-' + lesson.id + '">');
    h.push('<p class="crumb">Row ' + (index + 1) + ' of ' + LESSONS.length + '</p>');
    h.push('<h1>' + esc(lesson.title) + ' <small>' + esc(lesson.subtitle) + '</small></h1>');
    h.push('<p class="lead">' + esc(lesson.oneLiner) + '</p>');
    h.push('<div class="facts"><div><span class="k">Where it lives</span><span class="v">' + esc(lesson.layer) + '</span></div>');
    h.push('<div><span class="k">How this was made</span><span class="v"><code>' + esc(lesson.command) + '</code></span></div></div>');
    lesson.sections.forEach(function (s) { h.push(sectionHtml(s)); });
    if (lesson.steps) h.push('<section><h2>The conversation, step by step</h2><p class="hint">Dashed arrows are encrypted; a sniffer sees only that something of that size went by.</p><div class="diagram">' + diagram(lesson) + '</div></section>');
    h.push('<section><h2>What to look for</h2><ul class="lookfor">');
    lesson.lookFor.forEach(function (t) { h.push('<li>' + esc(t) + '</li>'); });
    h.push('</ul></section>');
    if (lesson.file) {
      h.push('<section class="packets"><div class="packets-head"><h2>The packets</h2><div class="dl-group">' +
        '<a class="dl" href="pcaps/' + encodeURIComponent(lesson.file) + '" download>Download .pcap</a>' +
        (lesson.downloads || []).map(function (d) { return '<a class="dl alt" href="' + esc(d.href) + '" download>' + esc(d.label) + '</a>'; }).join('') +
        '</div></div>' +
        '<p class="hint">Click a packet to expand its details. File: <code>' + esc(lesson.file) + '</code></p>' +
        '<div id="table" class="table-wrap"><p class="loading">Loading capture...</p></div></section>');
    }
    h.push('</article>');
    main.innerHTML = h.join('');
    main.scrollTop = 0;
    startAnimations();
    loadTextFiles();
    if (lesson.file) loadPackets(lesson);
    Array.prototype.forEach.call(main.querySelectorAll('.decrypt'), runDecrypt);
  }

  /* ---------- files shown verbatim (key log, certificate) ---------- */

  function fetchText(path) {
    if (textCache[path]) return Promise.resolve(textCache[path]);
    return fetch(path).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
      .then(function (t) { textCache[path] = t; return t; });
  }

  function loadTextFiles() {
    Array.prototype.forEach.call(main.querySelectorAll('pre.keyfile'), function (pre) {
      fetchText(pre.dataset.src).then(function (t) {
        var lines = t.replace(/\s+$/, '').split('\n'), max = +pre.dataset.lines || 0;
        if (max && lines.length > max) { pre.textContent = lines.slice(0, max).join('\n') + '\n... ' + (lines.length - max) + ' more lines'; }
        else pre.textContent = lines.join('\n');
      }).catch(function (e) { pre.textContent = 'Could not load ' + pre.dataset.src + ': ' + e.message; });
    });
  }

  /* ---------- packets ---------- */

  function fetchPcap(file) {
    if (pcapCache[file]) return Promise.resolve(pcapCache[file]);
    return fetch('pcaps/' + encodeURIComponent(file))
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.arrayBuffer(); })
      .then(function (buf) { var p = parsePcap(buf); pcapCache[file] = p; return p; });
  }

  function loadPackets(lesson) {
    var box = document.getElementById('table');
    fetchPcap(lesson.file).then(function (packets) {
      box.innerHTML = packetTable(packets);
      wireDetails(box, packets);
      wireCollapse(box);
    }).catch(function (e) {
      box.innerHTML = '<p class="error">Could not load the capture: ' + esc(e.message) + '. This page must be served over HTTP, not opened as a file.</p>';
    });
  }

  var FOLD_ABOVE = 80, FOLD_HEAD = 40, FOLD_TAIL = 8;

  function packetTable(packets) {
    var h = ['<table class="pk"><thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>'];
    var fold = packets.length > FOLD_ABOVE;
    packets.forEach(function (p, i) {
      var cls = 'proto-' + p.proto.toLowerCase().replace(/[^a-z0-9]/g, '');
      var folded = fold && i >= FOLD_HEAD && i < packets.length - FOLD_TAIL;
      if (fold && i === FOLD_HEAD) {
        h.push('<tr class="fold"><td colspan="7"><button type="button" class="fold-btn">Show the other ' +
          (packets.length - FOLD_HEAD - FOLD_TAIL) + ' packets (more connections doing the same thing)</button></td></tr>');
      }
      h.push('<tr class="pkt ' + cls + (folded ? ' folded' : '') + '" data-i="' + i + '" tabindex="0"' + (folded ? ' hidden' : '') + '>' +
        '<td class="n">' + p.no + '</td><td class="t">' + p.time.toFixed(6) + '</td>' +
        '<td>' + esc(p.src) + '</td><td>' + esc(p.dst) + '</td>' +
        '<td class="p">' + esc(p.proto) + '</td><td class="n">' + p.len + '</td>' +
        '<td class="info">' + esc(p.info) + '</td></tr>');
      h.push('<tr class="det" hidden><td colspan="7"><div class="det-inner">' + details(p) + '</div></td></tr>');
    });
    h.push('</tbody></table>');
    return h.join('');
  }

  function details(p) {
    var h = ['<div class="frame-line">Frame ' + p.no + ': ' + p.len + ' bytes on the wire, captured ' + p.time.toFixed(6) + ' s after the first packet</div>'];
    p.details.forEach(function (sec) {
      h.push('<div class="sec"><div class="sec-title">' + esc(sec.title) + '</div><table class="kv">');
      sec.rows.forEach(function (r) { h.push('<tr><th>' + esc(r[0]) + '</th><td>' + esc(r[1]).replace(/\n/g, '<br>') + '</td></tr>'); });
      h.push('</table></div>');
    });
    if (p.payload && p.payload.length) h.push('<div class="sec"><div class="sec-title">First bytes of the TLS payload, as a sniffer sees them</div><pre class="hex">' + hexDump(p.payload, 64) + '</pre></div>');
    return h.join('');
  }

  function hexDump(bytes, max) {
    var out = [], n = Math.min(bytes.length, max);
    for (var i = 0; i < n; i += 16) {
      var hexs = [], chars = '';
      for (var j = i; j < i + 16 && j < n; j++) { hexs.push(bytes[j].toString(16).padStart(2, '0')); chars += bytes[j] >= 32 && bytes[j] < 127 ? String.fromCharCode(bytes[j]) : '.'; }
      out.push(String(i).padStart(4, '0') + '  ' + hexs.join(' ').padEnd(47) + '  ' + esc(chars));
    }
    if (bytes.length > max) out.push('... ' + (bytes.length - max) + ' more bytes');
    return out.join('\n');
  }

  function wireCollapse(box) {
    var btn = box.querySelector('.fold-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      Array.prototype.forEach.call(box.querySelectorAll('tr.pkt.folded'), function (tr) { tr.hidden = false; });
      btn.parentNode.parentNode.remove();
    });
  }

  function wireDetails(box, packets) {
    Array.prototype.forEach.call(box.querySelectorAll('tr.pkt'), function (tr) {
      function toggle() {
        var det = tr.nextElementSibling;
        det.hidden = !det.hidden;
        tr.classList.toggle('open', !det.hidden);
      }
      tr.addEventListener('click', toggle);
      tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    });
  }

  /* ---------- decrypt a capture in the browser ---------- */

  function runDecrypt(box) {
    var file = box.dataset.file, keylogPath = box.dataset.keylog, hl = box.dataset.highlight ? new RegExp(box.dataset.highlight, 'g') : null;
    var wrong = false;
    function wrongKeylog(text) {
      /* flip one hex digit of every secret: the key log is "correct" to the eye, useless to AES */
      return text.split('\n').map(function (line) {
        var m = line.trim().split(/\s+/);
        if (m.length !== 3 || line[0] === '#') return line;
        var s = m[2], c = s[10] === 'f' ? '0' : String.fromCharCode(s.charCodeAt(10) + 1);
        return m[0] + ' ' + m[1] + ' ' + s.slice(0, 10) + c + s.slice(11);
      }).join('\n');
    }
    function run() {
      box.innerHTML = '<p class="loading">Decrypting the capture in your browser...</p>';
      Promise.all([fetchPcap(file), fetchText(keylogPath)]).then(function (r) {
        var packets = r[0], keylog = wrong ? wrongKeylog(r[1]) : r[1];
        return decryptCapture(packets, keylog).then(function (conns) { box.innerHTML = decryptHtml(conns, packets, hl, wrong); wireDecrypt(box); });
      }).catch(function (e) { box.innerHTML = '<p class="error">Could not decrypt here: ' + esc(e.message || String(e)) + '. Wireshark will still do it with the same files.</p>'; });
    }
    function wireDecrypt(el) {
      var t = el.querySelector('.key-toggle');
      if (t) t.addEventListener('click', function () { wrong = !wrong; run(); });
      Array.prototype.forEach.call(el.querySelectorAll('.more-btn'), function (b) {
        b.addEventListener('click', function () { var pre = b.previousElementSibling; pre.textContent = pre.dataset.full; b.remove(); });
      });
    }
    run();
  }

  function decryptHtml(conns, packets, hl, wrong) {
    var byNo = {}; packets.forEach(function (p) { byNo[p.no] = p; });
    var h = ['<div class="dec-head"><span class="dec-key ' + (wrong ? 'bad' : 'ok') + '">' + (wrong ? 'Using a key log with one hex digit changed' : 'Using the real key log') + '</span>' +
      '<button type="button" class="key-toggle">' + (wrong ? 'Back to the real keys' : 'Try it with a wrong key') + '</button></div>'];
    conns.forEach(function (c, i) {
      var opened = c.messages.filter(function (m) { return m.kind === 'http'; }).length;
      h.push('<div class="conn' + (c.failed ? ' failed' : '') + '"><div class="conn-head"><b>Connection ' + (i + 1) + '</b> ' + esc(c.client) + ' &rarr; ' + esc(c.server) +
        ' &middot; ' + esc(c.version) + ' &middot; ' + esc(c.cipher) + ' &middot; from frame ' + c.firstPacket + '<span class="conn-status">' + esc(c.status) + '</span></div>');
      if (!c.messages.length) { h.push('</div>'); return; }
      h.push('<div class="msgs">');
      c.messages.forEach(function (m) {
        var side = m.dir === 'client' ? 'c' : 's';
        if (m.kind === 'http') {
          var head = esc(m.text);
          if (hl) head = head.replace(hl, function (x) { return '<mark>' + x + '</mark>'; });
          h.push('<div class="msg ' + side + ' http"><div class="msg-title">' + esc(m.title) + ' <span class="msg-frame">frame ' + m.no + '</span></div><pre>' + head + '</pre>');
          if (m.body) {
            var isText = /^(text\/|application\/(javascript|json|xml))/.test(m.contentType) || /^\s*</.test(m.body.slice(0, 20));
            if (isText) {
              var lines = m.body.split('\n'), preview = lines.slice(0, 8).join('\n');
              h.push('<div class="msg-title">Body' + (m.note ? ' <span class="msg-note">' + esc(m.note) + '</span>' : '') + '</div><pre class="body" data-full="' + esc(m.body) + '">' + esc(preview) + (lines.length > 8 ? '\n...' : '') + '</pre>' +
                (lines.length > 8 ? '<button type="button" class="more-btn">Show all ' + lines.length + ' lines</button>' : ''));
            } else {
              h.push('<div class="msg-title">Body <span class="msg-note">' + m.body.length + ' bytes of binary (' + esc(m.contentType) + ')</span></div>');
            }
          }
          h.push('</div>');
        } else if (m.kind === 'fail') {
          h.push('<div class="msg ' + side + ' fail"><span class="msg-frame">frame ' + m.no + '</span> ' + esc(m.title) + ': ' + esc(m.text) + '</div>');
        } else {
          h.push('<div class="msg ' + side + ' meta"><span class="msg-frame">frame ' + m.no + '</span> ' + esc(m.title) + ': ' + esc(m.text) + '</div>');
        }
      });
      h.push('</div></div>');
    });
    return h.join('');
  }

  /* ---------- routing ---------- */

  function route() {
    stopAnimations();
    var id = location.hash.replace('#', '');
    var idx = -1;
    LESSONS.forEach(function (l, i) { if (l.id === id) idx = i; });
    setActive(idx >= 0 ? id : null);
    if (idx >= 0) renderLesson(LESSONS[idx], idx);
    else renderWelcome();
    document.title = (idx >= 0 ? LESSONS[idx].title + ' - ' : '') + 'Encryption and Protocols';
  }

  buildMenu();
  buildNav();
  (function () { var c = document.getElementById('net-cidr'); if (c) c.textContent = SITE.labNetwork; })();
  window.addEventListener('hashchange', route);
  route();
})();
