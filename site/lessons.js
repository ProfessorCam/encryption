/*
 * lessons.js - the teaching content for "Encryption and Protocols", one
 * object per row in the left column. app.js renders it; nothing here is code
 * you need to touch to change wording.
 *
 * Fields on a lesson:
 *   id, title, subtitle, oneLiner, layer, command   - header facts
 *   sections: [{ h, p: [html...], anim?, after?, steps?, files?, keylog?, decrypt?, table? }]
 *     anim     - key into ANIMATIONS (app.js): a looping packet-assembly animation
 *     packet   - { file, no }: one frame from a capture, shown as a small packet table with its details open
 *     steps    - numbered instructions (array of html strings)
 *     files    - download buttons: [{ label, href, note }]
 *     keylog   - path of a text file to show verbatim (the key log, the certificate ...)
 *     decrypt  - { file, keylog, highlight } decrypt that capture with that key log, right here
 *     table    - [[cells...], ...] a small comparison table (first row is the header)
 *   actors, steps                                    - the sequence diagram (optional)
 *   lookFor: [text...]                               - checklist for the packet table
 *
 *   Reading levels: any prose entry (oneLiner, layer, p, after, steps, table cells, lookFor,
 *   animation captions) may be a string (same at every level) or { s, m, e } for
 *   Simple / Moderate / Engineer. See level.js.
 *   file                                             - capture to show in the packet table (optional)
 *   downloads: [{ label, href }]                     - extra buttons next to "Download .pcap"
 */

var SITE = {
  image: 'professorcryan/https-demo:latest',   /* Docker Hub image of the live HTTPS server this site records */
  port: 8443,                                   /* host port; the container listens on 443 */
  labName: 'Lab WiFi',
  labNetwork: '192.168.110.0/23',
  menu: [
    { label: 'Frames & Packets', href: 'https://professorcam.github.io/frames/' },
    { label: 'Protocols', href: 'https://professorcam.github.io/pcap/' },
    { label: 'Encryption and Protocols', href: '#', current: true }
  ]
};

var FILES = {
  login: 'https-login-192.168.110.1.pcap',
  pages: 'https-github-pages.pcap',
  http: 'http-httpforever.pcap'          /* the plain HTTP capture from the HTTP row of the Protocols site */
};

var LESSONS = [
  {
    id: 'https',
    stack: 'tls',
    title: 'HTTPS',
    subtitle: 'What a sniffer sees',
    oneLiner: {
      s: 'HTTPS is the same web traffic as HTTP, but scrambled so that only your browser and the website can read it.',
      m: 'HTTPS is ordinary HTTP wrapped in TLS: the same requests and responses, scrambled so that only the two ends can read them.',
      e: 'HTTPS is HTTP carried in TLS records over TCP port 443: IP and TCP are unchanged, the HTTP bytes are encrypted and integrity-protected between the two endpoints.'
    },
    layer: {
      s: 'The scrambling happens after the address labels go on the envelope, so the addresses stay readable.',
      m: 'TLS sits between TCP (layer 4) and HTTP (layer 7). Everything below it stays visible.',
      e: 'TLS sits between TCP (layer 4) and HTTP (layer 7): a record layer over the TCP byte stream. Ethernet, IP and TCP headers stay in the clear.'
    },
    command: 'Chrome opened https://192.168.110.1/ and submitted the login form; tcpdump -i eth0 port 443 was running on the server',
    file: FILES.login,
    sections: [
      { h: 'Why HTTP was not enough', p: [{
        s: 'On the Protocols site, the HTTP row showed a plain web request. Everything in it, the page you asked for and the words you typed, went past in readable letters. Anyone sharing your Wi-Fi could read it with Wireshark, and so could every router along the way. Here is that packet again:',
        m: 'On the Protocols site, the HTTP row showed a plain HTTP request. Every header, every form field and the whole page came past in readable text. Anyone on the same Wi-Fi with Wireshark could read it, and so could every router between you and the server. Here is that packet again, frame 6 of the plain HTTP capture, with the bytes it carried:',
        e: 'The plain HTTP request in the HTTP row of the Protocols site carried its request line, headers and body as cleartext in the TCP payload; any host on the path, or on the same broadcast domain, could read it. Frame 6 of that capture again, payload included:'
      }], packet: { file: FILES.http, no: 6 }, after: [{
        s: 'HTTPS fixes that by scrambling the web part before it goes on the wire. The delivery part still works exactly as before, but the letter inside the envelope is now in code. The padlock in the address bar means two things and nothing more: the conversation is scrambled, and the website proved who it is.',
        m: 'HTTPS fixes that by putting <b>TLS</b> (Transport Layer Security) between TCP and HTTP. TCP still delivers the bytes in order, HTTP still says <code>GET /</code>, but in between the bytes are encrypted. The padlock in the address bar means exactly this and nothing more: the conversation is scrambled, and the certificate said the server is who it claims to be.',
        e: 'HTTPS inserts <b>TLS</b> (Transport Layer Security) between TCP and HTTP. TCP still delivers an ordered byte stream; that stream now consists of TLS records whose payload is the encrypted HTTP. The padlock asserts exactly two properties: confidentiality and integrity of the stream, and server authentication through the certificate chain.'
      }] },
      { h: 'Two kinds of keys', p: {
        s: [
          'Scrambling needs a key, and both sides have to agree on one without anyone listening in learning it. TLS does that with two kinds of key.',
          '<b>A lock and its key.</b> The website hands out a lock (its <b>public key</b>) to everyone. Anything closed with that lock can only be opened by the one matching key (the <b>private key</b>), which never leaves the server. So your browser can send a secret in a locked box, in front of an audience.',
          '<b>A shared secret code.</b> Once both sides know the secret, they use it as a fast code for all the real data. Same code both ways, and a new one for every visit.',
          'So: the lock to get started, the shared code to talk.'
        ],
        m: [
          'Encryption needs a key, and the two sides have to agree on one without anyone listening in being able to work it out. TLS uses two kinds of keys to solve that:',
          '<b>Asymmetric (public / private).</b> The server has a pair. The public key is in its certificate and is handed to everyone. Whatever is encrypted with the public key can only be opened with the private key, which never leaves the server. That is how the two sides agree on a secret in front of an audience.',
          '<b>Symmetric (the session key).</b> Once both sides share a secret, they derive a session key from it and use fast symmetric encryption (AES) for all the actual data. Same key both ways, a fresh one for every connection.',
          'So: asymmetric to set up, symmetric to talk. The rest of this site is about where those keys are and what you can do with them.'
        ],
        e: [
          'Key agreement has to happen over a channel the attacker can read. TLS combines two primitives:',
          '<b>Asymmetric (RSA here, RFC 8017).</b> The server\'s certificate carries its public key; the matching private key stays on the server. In the RSA key exchange the client encrypts a 48-byte pre-master secret under that public key, so only the private-key holder can recover it.',
          '<b>Symmetric (AES-128-GCM).</b> Both sides derive the master secret, then the key block, from the pre-master secret and the two randoms (the TLS 1.2 PRF, RFC 5246 section 8.1). All application data is AEAD-encrypted under those keys, a fresh set per connection.',
          'Asymmetric for key establishment, symmetric for bulk data. The remaining rows show where those keys live and what each one unlocks.'
        ]
      } },
      { h: 'One encrypted packet, built up', p: [{
        s: 'Frame 49 in the capture below carries the login form. Watch how the browser wraps it up, and notice which parts are still readable when it reaches the wire.',
        m: 'Frame 49 in the capture below carries the login form. Here is how the browser built it. Watch what is still readable when it reaches the wire.',
        e: 'Frame 49 carries the form submission as one TLS 1.2 Application Data record. The stages below show the encapsulation from HTTP plaintext to the 837-byte Ethernet frame; note which layers remain cleartext.'
      }], anim: 'tls-record' },
      { h: 'What is still visible, and what is hidden', p: {
        s: [
          'The addresses stay readable, so a sniffer still sees which computer talked to which website, roughly how much was sent, and when. That alone tells a nosy person quite a lot.',
          'What it cannot see: which page you asked for, what you typed into the form, and the page that came back. Those are inside the scrambled part, and without the key they look like random noise.'
        ],
        m: [
          'Encryption starts above TCP, so a sniffer still sees: both IP addresses, both ports (443 tells them it is HTTPS), how many bytes went each way and when, the name of the site the browser asked for (the SNI field of the Client Hello) and the server\'s certificate. Traffic analysis alone tells you a lot.',
          'What it cannot see: the URL path, the query string with the password, headers, cookies, and the page that came back. Those are inside the Application Data records, and without a key they are noise.'
        ],
        e: [
          'Cleartext for any on-path observer: IP addresses, TCP ports (443 implies HTTPS), record lengths and timing, the SNI extension of the Client Hello (absent here because the site was addressed by IP) and, in TLS 1.2, the server certificate. Traffic analysis on metadata alone is a real attack surface.',
          'Encrypted: the request line (path and query string, here including the password), all HTTP headers and cookies, and the response body. They are inside Application Data records (content type 23) and are indistinguishable from random bytes without the session keys.'
        ]
      } }
    ],
    actors: [{ name: 'Browser', addr: '192.168.110.50' }, { name: 'Web server', addr: '192.168.110.1 : 443' }],
    steps: [
      { from: 0, to: 1, label: 'TCP SYN / SYN-ACK / ACK  (frames 1 to 3, visible)' },
      { from: 0, to: 1, label: 'Client Hello: "here is what I can do"  (frame 4, visible)' },
      { from: 1, to: 0, label: 'Server Hello + Certificate: "use this; here is my public key"  (frame 6)' },
      { from: 0, to: 1, label: 'Client Key Exchange: secret, locked with the public key  (frame 8)' },
      { from: 0, to: 1, label: 'Finished  (encrypted from here on)', dashed: true },
      { from: 1, to: 0, label: 'Finished  (frame 14)', dashed: true },
      { from: 0, to: 1, label: 'Application Data = GET / HTTP/1.1  (frame 15)', dashed: true },
      { from: 1, to: 0, label: 'Application Data = 200 OK + the login page  (frames 20 to 27)', dashed: true },
      { from: 0, to: 1, label: 'Application Data = GET /action_page.php?name=Tux&pwd=...  (frame 49)', dashed: true },
      { from: 1, to: 0, label: 'Application Data = 200 OK "Sent over HTTPS"  (frames 54 to 57)', dashed: true }
    ],
    lookFor: [
      { s: 'Frames 1 to 3: the ordinary three-packet TCP hello, exactly like on the Protocols site. Nothing is scrambled yet.',
        m: 'Frames 1 to 3: a normal TCP handshake to port 443. Nothing about TLS changes TCP.',
        e: 'Frames 1 to 3: a standard TCP three-way handshake to port 443. TLS rides in the TCP payload; the transport layer is unmodified.' },
      { s: 'Frame 4, Client Hello: the browser says "here is what I can do". Open it and you can read every word.',
        m: 'Frame 4, Client Hello: open it. 16 cipher suites offered, the client random, and no server name because the site was addressed by IP. This is the only place the browser says what it can do.',
        e: 'Frame 4, Client Hello: 16 cipher suites, a 32-byte client random, no server_name extension (addressed by IP). The only message in which the client states its capabilities.' },
      { s: 'Frame 6: the server picks a method and sends its certificate, its ID card. ID cards are meant to be shown to everyone, so this is readable too.',
        m: 'Frame 6: the server picks RSA-AES128-GCM-SHA256 and sends its certificate in the clear. Certificates are public; that is the point of them.',
        e: 'Frame 6: the Server Hello selects TLS 1.2 with TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c); the Certificate message follows in cleartext, as TLS 1.2 always sends it.' },
      { s: 'Frame 8: the browser sends the secret, locked with the server\'s lock. From the very next message on, everything is scrambled.',
        m: 'Frame 8: Client Key Exchange, 258 bytes. A secret encrypted with the public key from the certificate. Then Change Cipher Spec, and the very next message is already unreadable.',
        e: 'Frame 8: Client Key Exchange, 258 bytes (2-byte length plus 256 bytes of RSA-2048 ciphertext), then Change Cipher Spec; the Finished that follows is already encrypted.' },
      { s: 'Frame 15: this is the browser asking for the page, the same request that was readable on the Protocols site. Here it is 754 bytes of noise.',
        m: 'Frame 15, Application Data, 754 bytes: that is GET / HTTP/1.1 with all its headers. Compare with the HTTP row on the Protocols site where the same request was readable.',
        e: 'Frame 15: Application Data, 754 bytes, carrying GET / HTTP/1.1 and its headers. Compare with the HTTP row on the Protocols site, where the same request was cleartext.' },
      { s: 'Frame 49: the login form with the password inside. Not one readable letter.',
        m: 'Frame 49: the login form. The URL with the password is in there. 771 bytes of TLS, and not one readable character.',
        e: 'Frame 49: the form submission. 771 bytes of TLS record carrying a 742-byte plaintext plus 8-byte nonce and 16-byte tag; no plaintext bytes on the wire.' },
      { s: 'The browser opened four separate connections to be quick. The third and fourth start with a shorter greeting, explained in {{row:handshake}}.',
        m: 'The browser opened four connections (ports 46484, 46500, 46516, 46522). Chrome does that to be quick; connections 3 and 4 use a shorter handshake, explained in {{row:handshake}}.',
        e: 'Four connections (client ports 46484, 46500, 46516, 46522). Connections 3 and 4 use abbreviated handshakes (session ID resumption), covered in {{row:handshake}}.' }
    ]
  },

  {
    id: 'handshake',
    stack: 'tls',
    title: 'The TLS handshake',
    subtitle: 'From Client Hello to Finished',
    oneLiner: {
      s: 'Before any web page moves, browser and server have a short conversation to agree on how to scramble things and on a shared secret.',
      m: 'Before a single byte of HTTP is sent, the two sides agree on a version, a cipher, and a secret, in four packets that are mostly readable.',
      e: 'The TLS 1.2 handshake negotiates version and cipher suite, authenticates the server and establishes the master secret in two round trips; frames 4, 6, 8 and 14 carry all of it.'
    },
    layer: {
      s: 'This is the greeting at the start of every secure connection. Most of it is still readable.',
      m: 'TLS handshake messages ride inside TLS records, inside TCP. Frames 4, 6, 8 and 14 are the whole thing.',
      e: 'Handshake protocol messages (content type 22) inside TLS records inside TCP; Change Cipher Spec is content type 20. Frames 4, 6, 8 and 14 are the whole thing.'
    },
    command: 'Same capture as the HTTPS row; look at the first connection, client port 46484',
    file: FILES.login,
    sections: [
      { h: 'Step by step', p: {
        s: [
          '<b>Hello from the browser (frame 4).</b> The browser lists the scrambling methods it knows and sends a big random number.',
          '<b>Hello from the server (frame 6).</b> The server picks one method from the list, sends its own random number, and its certificate: the ID card that carries its lock (public key).',
          '<b>The secret (frame 8).</b> The browser makes up a secret, locks it with the server\'s lock and sends it. Only the server\'s private key can open it. Both sides now mix the secret with the two random numbers to make the code they will use.',
          '<b>Finished (frames 8 and 14).</b> Each side says "from now on I am scrambling" and sends a scrambled summary of the whole conversation so far. If both summaries match, nobody tampered with the greeting. The next message is the request for the web page.'
        ],
        m: [
          '<b>Client Hello (frame 4).</b> The browser lists the TLS versions and cipher suites it supports, sends 32 random bytes (the <i>client random</i>) and, for TLS 1.3, its half of a key exchange in advance. Chrome also throws in deliberate junk values called GREASE so servers never learn to rely on a fixed list.',
          '<b>Server Hello, Certificate, Server Hello Done (frame 6).</b> The server picks one version and one cipher suite from the list, sends its own 32 random bytes, and its certificate. The certificate carries the public key and is sent in the clear.',
          '<b>Client Key Exchange (frame 8).</b> With the RSA cipher chosen here, the browser makes a 48-byte <i>pre-master secret</i>, encrypts it with the server\'s public key and sends it. Only the private key can open it. Both sides now mix pre-master secret + client random + server random into the <i>master secret</i>, and derive the session keys from that.',
          '<b>Change Cipher Spec and Finished (frames 8 and 14).</b> Each side announces "from here on I am encrypting" and sends a Finished message, encrypted with the new keys, containing a hash of everything said so far. If the hashes agree, nobody tampered with the handshake. The next record is HTTP.'
        ],
        e: [
          '<b>ClientHello (frame 4).</b> client_version, 32-byte client random, session ID, 16 cipher suites, and extensions including supported_versions (1.3 and 1.2), a key_share for x25519 that a TLS 1.2 server ignores, and GREASE values (RFC 8701).',
          '<b>ServerHello, Certificate, ServerHelloDone (frame 6).</b> The server fixes TLS 1.2 and TLS_RSA_WITH_AES_128_GCM_SHA256, sends its 32-byte server random and an X.509 certificate (RFC 5280) carrying the RSA-2048 public key, all in cleartext.',
          '<b>ClientKeyExchange (frame 8).</b> A 48-byte pre-master secret (2 version bytes + 46 random bytes), RSA PKCS#1 v1.5 encrypted under the certificate\'s public key. master_secret = PRF(pre_master_secret, "master secret", client_random + server_random), 48 bytes; the key block (client and server write keys and IVs) is expanded from it.',
          '<b>ChangeCipherSpec and Finished (frames 8 and 14).</b> Each side switches to the negotiated cipher and sends Finished: 12 bytes of PRF(master_secret, "client finished" or "server finished", Hash(handshake_messages)), encrypted. A mismatch aborts; a match confirms an untampered transcript. The next record is Application Data.'
        ]
      } },
      { h: 'Why this lab uses the RSA key exchange', p: {
        s: [
          'This server was set up the old way on purpose: the browser chooses the secret and sends it locked with the server\'s lock. That means whoever holds the server\'s private key can open the secret from a recording and read everything. That is exactly what you will do in {{row:decrypt}}.',
          'Real websites stopped doing this years ago. Today both sides make throwaway numbers and each works out the same secret without it ever being sent, not even in a locked box. So even if the server\'s key leaks next year, old recordings stay unreadable. That is called <b>forward secrecy</b>.'
        ],
        m: [
          'The server was set up on purpose to offer only <b>RSA key exchange</b> ciphers and only TLS 1.2. With those, the whole secret is decided by the client and sent encrypted under the server\'s public key. Whoever holds the private key can decrypt the Client Key Exchange, recover the pre-master secret, and derive the same session keys: that is how Wireshark\'s "RSA keys list" method works, and it is what you will do in {{row:decrypt}}.',
          'Real websites stopped doing this years ago. Modern TLS uses ephemeral Diffie-Hellman (the ECDHE ciphers and all of TLS 1.3): each side sends a throwaway public value, both compute the same secret, and the secret is never on the wire at all, not even encrypted. That property is called <b>forward secrecy</b>: even if the server\'s private key leaks next year, last year\'s captures stay unreadable. Chrome offered those ciphers first in frame 4; look at the order of the list.'
        ],
        e: [
          'The server offers only TLS 1.2 RSA key-exchange suites, so the pre-master secret crosses the wire encrypted under the server\'s long-term RSA key. The private key therefore decrypts the ClientKeyExchange of any recorded session and yields the same master secret and key block; that is the mechanism behind Wireshark\'s RSA keys list, used in {{row:decrypt}}.',
          'Every current deployment uses ephemeral (EC)DHE: TLS_ECDHE_* suites in 1.2 and all of TLS 1.3 (RFC 8446), where the server key only signs the handshake. The shared secret is computed, never transmitted, so compromise of the long-term key does not expose past sessions: <b>forward secrecy</b>. Chrome lists those suites first in frame 4; the TLS_RSA_* suites are last.'
        ]
      } },
      { h: 'The short handshake: resumption', p: [{
        s: 'The third and fourth connections skip most of the greeting. The browser says "remember me from connection 1?", the server does, and they reuse the old secret. Fewer packets, and none of the heavy maths.',
        m: 'Connections 3 and 4 (client ports 46516 and 46522) look different: Client Hello, then a Server Hello with Change Cipher Spec and Finished straight away, and no Certificate or Client Key Exchange. The browser presented the session ID from connection 1, the server still remembered the master secret, and they skipped the expensive part. Two packets fewer, and no public-key maths.',
        e: 'Connections 3 and 4 (client ports 46516 and 46522) resume by session ID: a ClientHello carrying the session ID from connection 1, then ServerHello + ChangeCipherSpec + Finished in one packet, with no Certificate or ClientKeyExchange. Both sides reuse the cached master secret and expand a fresh key block from the new randoms. One round trip and no RSA operation.'
      }] }
    ],
    actors: [{ name: 'Browser', addr: '192.168.110.50 : 46484' }, { name: 'Web server', addr: '192.168.110.1 : 443' }],
    steps: [
      { from: 0, to: 1, label: 'Client Hello: TLS 1.3 / 1.2, 16 cipher suites, client random  (frame 4)' },
      { from: 1, to: 0, label: 'Server Hello: TLS 1.2, RSA-AES128-GCM-SHA256, server random  (frame 6)' },
      { from: 1, to: 0, label: 'Certificate: CN=localhost, RSA 2048-bit public key  (frame 6)' },
      { from: 1, to: 0, label: 'Server Hello Done  (frame 6)' },
      { from: 0, to: 1, label: 'Client Key Exchange: pre-master secret, encrypted with the public key  (frame 8)' },
      { from: 0, to: 1, label: 'Change Cipher Spec, then Finished  (frame 8)', dashed: true },
      { from: 1, to: 0, label: 'New Session Ticket, Change Cipher Spec, Finished  (frame 14)', dashed: true },
      { from: 0, to: 1, label: 'Application Data  (frame 15, HTTP begins)', dashed: true }
    ],
    lookFor: [
      { s: 'Frame 4: open the Client Hello and look at the list of methods the browser offered. The old-fashioned one this server uses is at the very bottom.',
        m: 'Frame 4: expand the Client Hello. The cipher list begins with GREASE, then the three TLS 1.3 suites, then ECDHE, and the RSA ones last. Chrome offers the RSA key exchange only as a last resort.',
        e: 'Frame 4: cipher_suites order is GREASE, the three TLS 1.3 AEAD suites, the ECDHE suites, then TLS_RSA_* last. Chrome offers the RSA key exchange only as a last resort.' },
      { s: 'Frame 6: the server picks that last-resort method. The certificate in the same frame is readable by anyone.',
        m: 'Frame 6: the Server Hello picks the second-to-last kind on that list. Also in frame 6: a Certificate of 815 bytes, readable by anyone.',
        e: 'Frame 6: ServerHello selects TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c). The Certificate message is 815 bytes of cleartext.' },
      { s: 'Frame 8: the locked secret, then straight away the first scrambled message.',
        m: 'Frame 8: 258 bytes of Client Key Exchange (256 bytes is the RSA-2048 ciphertext plus a 2-byte length), immediately followed by Change Cipher Spec and one Encrypted Handshake Message: the Finished.',
        e: 'Frame 8: ClientKeyExchange 258 bytes (2-byte length plus 256-byte RSA-2048 ciphertext), ChangeCipherSpec, then one Encrypted Handshake Message: the Finished.' },
      { s: 'Frame 14: the server\'s reply in the same order. After this, nothing in the connection is readable.',
        m: 'Frame 14: the server\'s answer, in the same order. After this frame there is no more readable TLS in this connection.',
        e: 'Frame 14: NewSessionTicket, ChangeCipherSpec, Finished. No further cleartext handshake data in this connection.' },
      { s: 'Frames 44, 46, 48: the third connection, with the short greeting.',
        m: 'Frames 44, 46, 48: connection 3. Client Hello, then Server Hello + Change Cipher Spec + Finished in one 207-byte packet. That is session resumption.',
        e: 'Frames 44, 46, 48: connection 3. ClientHello, then ServerHello + ChangeCipherSpec + Finished in one 207-byte packet: session ID resumption.' },
      { s: 'Look at the times: the whole greeting took about 12 thousandths of a second here. On the real internet it takes longer, which is one reason pages take a moment to start loading.',
        m: 'Notice the timing: from SYN (frame 1) to the first HTTP request (frame 15) took 12 milliseconds. On a real network the handshake costs one or two round trips before any page can load.',
        e: 'Timing: SYN (frame 1) to the first Application Data (frame 15) is 12 ms on this LAN. A full TLS 1.2 handshake costs two RTTs after the TCP handshake; resumption and TLS 1.3 cost one.' }
    ]
  },

  {
    id: 'keys',
    stack: 'tls',
    chip: 'files',
    title: 'The keys',
    subtitle: 'Public, private, and the key log',
    oneLiner: {
      s: 'Three files can unlock this recording: the server\'s private key, the notes the server kept, and the notes the browser kept. All three lead to the same secret code.',
      m: 'Three files can open this capture: the server\'s private key, the key log the server wrote, and the key log the browser wrote. They all lead to the same session key.',
      e: 'Three files decrypt this capture: the server\'s RSA private key (recovers the pre-master secret from frame 8) and the key logs written by server and browser (the master secret directly). All yield the same key block.'
    },
    layer: {
      s: 'Nothing here is a packet. These are the files the two ends kept on their own disks.',
      m: 'Nothing in this row is a packet. These are the files the two ends kept.',
      e: 'No packets here: PEM-encoded key material and NSS-format key log files kept by the endpoints.'
    },
    command: 'openssl req -x509 -newkey rsa:2048 ... on the server; SSLKEYLOGFILE and Python\'s ssl.SSLContext.keylog_filename on the two ends',
    sections: [
      { h: 'The certificate and its public key', p: {
        s: [
          'When the server started it made itself a lock and key pair, and put the lock (the public key) inside a certificate, a kind of ID card. Nobody official signed this ID card, which is why a browser warns about it: the lock works, but no trusted authority has said who it belongs to. Real websites get their ID card signed by an authority the browser already trusts.',
          'Frame 6 of the capture carries exactly this file.'
        ],
        m: [
          'The server made itself a certificate when it started: a 2048-bit RSA key pair, with the public half wrapped in a certificate for the name <code>localhost</code>, signed by nobody but itself. That is why a browser shows a warning for it: the key is fine, but no authority vouched that it belongs to whoever answers at that address. Real sites get their certificate signed by an authority the browser already trusts.',
          'Frame 6 of the capture carries exactly this file. You could copy the bytes out of the packet and get the same certificate.'
        ],
        e: [
          'At start-up the server generated an RSA-2048 key pair and a self-signed X.509 certificate for CN=localhost (<code>openssl req -x509</code>). The browser warning is a chain-validation failure, not a key problem: no trusted CA signed it. Public sites present a chain that ends in a root in the browser\'s trust store.',
          'The Certificate message in frame 6 carries this file DER-encoded, byte for byte; the PEM below is its base64 form.'
        ]
      }, keylog: 'keys/server.crt' },
      { h: 'The private key', p: {
        s: [
          'This is the file a real server must never give away. Here it is on purpose, so you can see what it does: it opens the locked secret in frame 8, and from there the whole conversation. Wireshark can be given this file directly.',
          'Against a modern website this file would be useless, because the secret is never sent locked with it. {{Row:yourbrowser}} shows that.'
        ],
        m: [
          'This is the file that must never leave a real server. Here it is, on purpose, because the lab is about seeing what it can do. With the RSA key exchange it decrypts the Client Key Exchange in frame 8, and from there everything. Wireshark takes it under <i>Preferences, Protocols, TLS, RSA keys list</i>.',
          'On the modern web this file would be useless to an eavesdropper: with TLS 1.3 and ECDHE the secret is never encrypted with it. {{Row:yourbrowser}} shows that with a real site.'
        ],
        e: [
          'The RSA private key, PEM. With the RSA key exchange it decrypts the ClientKeyExchange in frame 8, recovering the pre-master secret and hence the master secret and key block. Wireshark: <i>Preferences, Protocols, TLS, RSA keys list</i>.',
          'Under (EC)DHE or TLS 1.3 the key only signs; nothing on the wire is encrypted under it, so it cannot decrypt a capture. {{Row:yourbrowser}} demonstrates this against a real site.'
        ]
      }, files: [{ label: 'server.key', href: 'keys/server.key', note: 'RSA private key, PEM' }, { label: 'server.crt', href: 'keys/server.crt', note: 'the certificate' }] },
      { h: 'The key log', p: {
        s: [
          'Both ends of a secure connection know the secret code, so either one can write it down. The key log is that notebook: one line per connection with a label, the browser\'s random number from the greeting, and the secret. Wireshark matches each line to a connection using that random number, which is readable in the capture.',
          'The server wrote this file while the recording was made. Four lines, one per connection; connections 2, 3 and 4 reused the secret from connection 1:'
        ],
        m: [
          'Both ends of a TLS connection know the session secrets, so both can write them down. The format is one line per connection: a label, the 32-byte client random from the Client Hello, and the secret. Wireshark matches lines to connections by the client random, which is in the capture in the clear.',
          'The server wrote this file while the capture was being made. Four lines, one per connection; connections 2, 3 and 4 share the master secret of connection 1 because of resumption:'
        ],
        e: [
          'NSS key log format, one line per connection: <code>CLIENT_RANDOM</code>, the 32-byte client random in hex, the 48-byte master secret in hex. Wireshark keys the lookup on the client random, which is cleartext in the ClientHello.',
          'Written by the server through <code>ssl.SSLContext.keylog_filename</code> during the capture. Four lines; connections 2 to 4 repeat the master secret of connection 1 because of session resumption:'
        ]
      }, keylog: 'keys/keylog.txt', after: [{
        s: 'The browser wrote its own notebook at the same time. Filter it to this server and it has the same lines, because both sides worked out the same secret. {{Row:yourbrowser}} uses this browser-side trick on a real website.',
        m: 'Chrome, started with <code>--ssl-key-log-file</code>, wrote its own file at the same time. Filter it to the lines for this server and it is identical, because both sides computed the same secrets. That is the whole idea of TLS. {{Row:yourbrowser}} uses this browser-side trick against a real site.',
        e: 'Chrome, started with <code>--ssl-key-log-file</code>, logged the same connections. Filtered to this server the lines are identical, as they must be: both endpoints computed the same master secret. {{Row:yourbrowser}} applies the browser-side log to a TLS 1.3 site.'
      }], files: [{ label: 'keylog.txt', href: 'keys/keylog.txt', note: 'written by the server' }, { label: 'chrome-keylog.txt', href: 'keys/chrome-keylog.txt', note: 'written by the browser, same lines' }] },
      { h: 'Which key opens what', p: [], table: [
        ['', 'Private key (server.key)', 'Key log (keylog.txt)'],
        ['Who has it', 'Only the server', 'Whichever end wrote it: the server, or the browser'],
        [{ s: 'Opens this lab\'s recording', m: 'Opens TLS 1.2 with RSA key exchange (this lab)', e: 'TLS 1.2, RSA key exchange (this lab)' }, 'Yes', 'Yes'],
        [{ s: 'Opens a real website\'s traffic', m: 'Opens TLS 1.2 with ECDHE, or TLS 1.3 (the real web)', e: 'TLS 1.2 with (EC)DHE, or TLS 1.3 (the real web)' },
         { s: 'No: the secret was never locked with it', m: 'No: the secret was never encrypted with it', e: 'No: the key only signs the handshake' }, 'Yes'],
        ['Works after the connection is over', 'Yes, on any old capture', 'Only for connections logged at the time'],
        ['Wireshark setting', 'TLS, RSA keys list', 'TLS, (Pre)-Master-Secret log filename']
      ] }
    ],
    lookFor: [
      { s: 'The label at the start of each key-log line says which kind of TLS it came from. This file has one kind; {{row:yourbrowser}} shows the newer kind, which needs several lines per connection.',
        m: 'The key log labels: CLIENT_RANDOM lines are TLS 1.2. TLS 1.3 uses several secrets per connection (CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0 and so on). {{Row:yourbrowser}} shows those.',
        e: 'Labels: CLIENT_RANDOM is the single TLS 1.2 master secret. TLS 1.3 logs CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 and EXPORTER_SECRET per connection. {{Row:yourbrowser}} shows those.' },
      { s: 'The middle part of every key-log line is the browser\'s random number. You can find the same characters inside frame 4 of the recording.',
        m: 'The second field of every key log line is a client random. Find the same 64 hex characters in the Client Hello of frame 4.',
        e: 'Field 2 of each line is the 32-byte client random (64 hex characters); match it to the Random field of the ClientHello in frame 4.' },
      { s: 'A key file is just a block of letters and digits between a BEGIN line and an END line.',
        m: 'A PEM file is just base64 between BEGIN and END lines. The private key is 1704 characters; the certificate is 1151.',
        e: 'PEM is base64 DER between BEGIN and END lines: the private key is 1704 characters, the certificate 1151.' }
    ]
  },

  {
    id: 'decrypt',
    stack: 'tls',
    title: 'Decrypt the recorded session',
    subtitle: 'In Wireshark, and right here',
    oneLiner: {
      s: 'Give Wireshark the notebook of secrets, or the server\'s private key, and the scrambled traffic turns back into a readable web page, password and all.',
      m: 'Give Wireshark the key log or the private key and the Application Data becomes HTTP again, password included.',
      e: 'Load keylog.txt (master secret) or server.key (RSA private key) into Wireshark\'s TLS preferences and the Application Data records decrypt to HTTP, query string with the password included.'
    },
    layer: {
      s: 'This is the recording from {{row:https}}. The packets are the same; only what you can read has changed.',
      m: 'This is the capture from {{row:https}}, decrypted. Nothing in the packets changes; only your ability to read them does.',
      e: 'Same capture as {{row:https}}. The bytes on disk are unchanged; the dissector gains the key block and decrypts the records in place.'
    },
    command: 'Wireshark: Edit, Preferences, Protocols, TLS. Then Follow, HTTP Stream.',
    file: FILES.login,
    downloads: [{ label: 'keylog.txt', href: 'keys/keylog.txt' }, { label: 'server.key', href: 'keys/server.key' }],
    sections: [
      { h: 'Method 1: the key log (works on every Wireshark)', p: [{
        s: 'This is the method real analysts use. It works for every version of TLS.',
        m: 'This is the method real analysts use, and it works for any TLS version.',
        e: 'The (Pre)-Master-Secret log method: Wireshark matches CLIENT_RANDOM lines to connections and rebuilds the key block. Version-independent, and the only method that works for TLS 1.3.'
      }], steps: [
        'Download the capture and <code>keylog.txt</code> with the buttons at the bottom of this page.',
        'Open the capture in Wireshark. Type <code>tls</code> in the display filter: everything after frame 14 is Application Data, unreadable.',
        'Edit, Preferences, Protocols, TLS. In <i>(Pre)-Master-Secret log filename</i> choose <code>keylog.txt</code>. OK.',
        'The Protocol column now says HTTP for frames 15, 20, 33, 34, 49 and 54. Right-click frame 49, Follow, HTTP Stream.',
        'Read the request line: <code>GET /action_page.php?name=Tux&amp;pwd=Penguin2026%21</code>. The <code>%21</code> is an exclamation mark, URL-encoded.'
      ] },
      { h: 'Method 2: the private key (RSA key exchange only)', p: [{
        s: 'Same result by a different door. It only works because this server used the old-fashioned way of sharing the secret. Some versions of Wireshark have this feature switched off; if nothing happens, use Method 1.',
        m: 'Same result by a different door. This only works because the server chose an RSA key-exchange cipher, and some Wireshark builds have this feature switched off, so use Method 1 if it does nothing.',
        e: 'RSA keys list: Wireshark decrypts the ClientKeyExchange with the private key and derives the key block. Works only for RSA key-exchange suites, and some builds are compiled without it; fall back to Method 1 if nothing changes.'
      }], steps: [
        'Download <code>server.key</code>.',
        'Edit, Preferences, Protocols, TLS, <i>RSA keys list</i>, Edit. Add a row: key file = server.key, leave IP, port and protocol empty. OK twice.',
        'Wireshark decrypts frame 8 with the private key, recovers the pre-master secret, and derives the same session keys. Everything decodes exactly as before.',
        'Remove the key again, and the same frames go back to Application Data. Nothing changed but your key.'
      ] },
      { h: 'Do it live instead of from the recording', p: [{
        s: 'The recording is handy, but the server that made it is on Docker Hub, so you can record your own login instead. Run it, capture on your own machine, and the page itself hands you every file you need:',
        m: 'The recording is convenient, but the server that made it is on Docker Hub, so you can capture your own login instead. Run it on your machine, capture on the loopback interface, and every file the steps above need is handed to you by the page itself:',
        e: 'The image on Docker Hub runs the same server. Run it locally, capture on loopback, and the confirmation page serves the key log and private key for that session:'
      }], steps: [
        '<code>docker run -d --name https-demo -p ' + SITE.port + ':443 ' + SITE.image + '</code>',
        'Start Wireshark on the loopback interface (<i>lo</i>, or "Adapter for loopback"), filter <code>tls</code>.',
        'Open <a href="https://localhost:' + SITE.port + '/">https://localhost:' + SITE.port + '/</a>, accept the certificate warning (a fresh self-signed key is generated every time the container starts), type a password, Submit.',
        'The confirmation page links to <code>keylog.txt</code> and <code>server.key</code> for your own session. Load either one in Wireshark exactly as above and find your password.',
        'Finished: <code>docker rm -f https-demo</code>.'
      ] },
      { h: 'The same thing, done in your browser', p: [{
        s: 'To prove there is no trick, this page does what Wireshark does, right here in your browser: it takes the secret from the notebook, works out the code, and unscrambles every record. The result is below. Switch to the wrong key and watch every record fail.',
        m: 'To prove there is no trick, this page does what Wireshark does, in JavaScript: it reassembles the TCP streams from the packets below, takes the master secret from <code>keylog.txt</code>, derives the AES session keys with the TLS 1.2 key expansion, and opens every record with AES-GCM using the browser\'s own crypto. The result is below. Flip to the wrong key and watch every record fail its integrity check.',
        e: 'This page reimplements the dissector in JavaScript: TCP stream reassembly, the TLS 1.2 PRF (RFC 5246) to expand the master secret from <code>keylog.txt</code> into the AES-128-GCM key block, then WebCrypto AES-GCM per record with the 8-byte explicit nonce and 16-byte tag. Switch to the wrong key and every record fails authentication.'
      }], decrypt: { file: FILES.login, keylog: 'keys/keylog.txt', highlight: 'pwd=[^ &\\s]+' } }
    ],
    actors: [{ name: 'Browser', addr: '192.168.110.50' }, { name: 'Web server', addr: '192.168.110.1 : 443' }],
    steps: [
      { from: 0, to: 1, label: 'frame 15: GET / HTTP/1.1  Host: 192.168.110.1', dashed: true },
      { from: 1, to: 0, label: 'frames 20 to 27: HTTP/1.0 200 OK, text/html, 21,604 bytes: the login page', dashed: true },
      { from: 0, to: 1, label: 'frame 33: GET /favicon.ico', dashed: true },
      { from: 1, to: 0, label: 'frames 34, 36: HTTP/1.0 404 Not Found', dashed: true },
      { from: 0, to: 1, label: 'frame 49: GET /action_page.php?name=Tux&pwd=Penguin2026%21', dashed: true },
      { from: 1, to: 0, label: 'frames 54 to 57: HTTP/1.0 200 OK "Sent over HTTPS, encrypted end to end"', dashed: true }
    ],
    lookFor: [
      { s: 'Before the key: frame 49 is 837 bytes of noise. After: the request with the password in it. Same bytes on disk.',
        m: 'Before the keys: frame 49 is "Application Data", 837 bytes. After: "GET /action_page.php?name=Tux&pwd=Penguin2026%21 HTTP/1.1". Same bytes on disk.',
        e: 'Frame 49 before: Application Data, 837 bytes on the wire. After: GET /action_page.php?name=Tux&pwd=Penguin2026%21 HTTP/1.1. The file is unchanged; only the dissection differs.' },
      { s: 'The password was in the web address because the form used GET. HTTPS hid it from the network, but the server\'s log and your browser history still have it. Scrambled is not the same as private.',
        m: 'The password went over the wire in the URL because the form used GET. HTTPS hid it from the network, but it is still in the server log and the browser history. Encryption is not the same as privacy.',
        e: 'The credential is in the query string because the form method is GET. TLS protects it on the path only; it still lands in server access logs, the Referer header and browser history. Confidentiality in transit is not privacy.' },
      { s: 'Frame 20 is the server\'s answer. Even the boring headers were hidden; you only see them because you have the key.',
        m: 'The 200 OK in frame 20 says HTTP/1.0 and Server: HTTPSDemo/1.0. Headers are hidden by TLS too; you only see them because you have the key.',
        e: 'Frame 20: HTTP/1.0 200 OK, Server: HTTPSDemo/1.0. Headers are inside the encrypted record; visible only with the key block.' },
      { s: 'Frames 21, 23, 24 are one big scrambled chunk split across three packets. Wireshark glues them back together before unscrambling; so does this page.',
        m: 'Frames 21, 23, 24: one TLS record of 16,408 bytes, the maximum allowed, split across three TCP segments. Wireshark reassembles them before decrypting; so does this page.',
        e: 'Frames 21, 23, 24: a single 16,408-byte TLS record (2^14 bytes of plaintext plus nonce and tag, the maximum) spanning three TCP segments. Reassembly precedes decryption, in Wireshark and here.' },
      { s: 'Wrong key: change a single character of the secret and nothing comes out, not even garbage. The built-in tamper check refuses every record.',
        m: 'Wrong key: with one hex digit of the master secret changed, AES-GCM refuses every record. It does not produce garbage, it produces nothing. That is the integrity tag doing its job.',
        e: 'Wrong key: alter one hex digit of the master secret and AES-GCM fails the tag check on every record. No plaintext is emitted; AEAD authenticates before it releases anything.' }
    ]
  },

  {
    id: 'yourbrowser',
    stack: 'tls',
    title: 'Decrypt your own browser',
    subtitle: 'SSLKEYLOGFILE against a real site',
    oneLiner: {
      s: 'Your own browser will write its secret codes to a file if you ask it to. With that file, Wireshark can unscramble your own traffic to any website.',
      m: 'Your browser will write its session secrets to a file if you ask. With that file, Wireshark decrypts your own traffic to any HTTPS site, including this one.',
      e: 'Browsers honour SSLKEYLOGFILE and append NSS-format traffic secrets per connection; Wireshark decrypts the resulting TLS 1.3 sessions with no server key involved.'
    },
    layer: {
      s: 'A real website on the internet, done the modern way. No private key involved, and none would help.',
      m: 'TLS 1.3 to a real server on the internet. No private key involved, and none would help.',
      e: 'TLS 1.3 (RFC 8446) to GitHub Pages: x25519 key share, TLS_AES_128_GCM_SHA256. The server key signs only; no private key can decrypt this.'
    },
    command: 'chromium --ssl-key-log-file=keylog.txt --disable-http2 https://professorcam.github.io/pcap/  with tcpdump port 53 or port 443 alongside',
    file: FILES.pages,
    downloads: [{ label: 'github-pages-keylog.txt', href: 'keys/github-pages-keylog.txt' }],
    sections: [
      { h: 'Why the private-key trick does not work out there', p: {
        s: [
          'Real websites use the modern way: both sides make throwaway numbers and each works out the same secret without ever sending it. The website\'s private key is only used to sign the greeting and prove who it is. Even the website itself could not unscramble a recording of your visit afterwards.',
          'But the two ends still know the secret, and one of those ends is your browser. Chrome, Edge, Brave and Firefox will write every connection\'s secrets to a file if you set a special variable named <code>SSLKEYLOGFILE</code> before starting them. Wireshark reads that file directly.'
        ],
        m: [
          'GitHub Pages, like every modern site, speaks TLS 1.3. The secret comes from an ephemeral Diffie-Hellman exchange (x25519 in this capture): each side sends a throwaway public value and both compute the shared secret; it is never transmitted. GitHub\'s private key only signs the handshake to prove identity. Even GitHub cannot decrypt a recording of your visit afterwards.',
          'But the endpoints still know the secrets, and one of the endpoints is your browser. Chrome, Edge, Brave and Firefox all honour an environment variable named <code>SSLKEYLOGFILE</code>: set it before the browser starts and every connection\'s secrets are appended to that file in the same format as {{row:keys}}. Wireshark reads it directly.'
        ],
        e: [
          'GitHub Pages negotiates TLS 1.3. The shared secret comes from an ephemeral x25519 ECDHE exchange: each side sends a public key share, both compute the same secret, nothing secret is transmitted. The certificate key signs the transcript (CertificateVerify) only. A recording cannot be decrypted with it, by anyone.',
          'The endpoints hold the secrets, and the browser is an endpoint. Chrome, Edge, Brave and Firefox append per-connection secrets to the file named by the <code>SSLKEYLOGFILE</code> environment variable, in the same NSS key log format as {{row:keys}}; Wireshark consumes it directly.'
        ]
      } },
      { h: 'Do it yourself', p: [{
        s: 'Close the browser completely first; it only looks at the setting when it starts. School laptops and Chromebooks usually will not let you do this, which is what the recorded visit further down is for.',
        m: 'Close the browser completely first; it only reads the variable at startup. Chromebooks and managed school laptops will usually not allow this, which is what the recorded session further down is for.',
        e: 'The variable is read once at process start, so quit the browser fully. Managed devices typically block environment changes; the recorded session below covers that case.'
      }], steps: [
        '<b>Windows:</b> Settings, System, About, Advanced system settings, Environment Variables. Add a user variable <code>SSLKEYLOGFILE</code> with value <code>C:\\Users\\you\\keylog.txt</code>. Or in PowerShell: <code>$env:SSLKEYLOGFILE="$HOME\\keylog.txt"; &amp; "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"</code>',
        '<b>macOS:</b> in Terminal: <code>SSLKEYLOGFILE=$HOME/keylog.txt open -a "Google Chrome"</code>  (or Firefox).',
        '<b>Linux:</b> <code>SSLKEYLOGFILE=$HOME/keylog.txt google-chrome</code>  or  <code>SSLKEYLOGFILE=$HOME/keylog.txt firefox</code>.',
        'Start Wireshark, capture on your Wi-Fi interface, display filter <code>tls</code>.',
        'In the browser, open <a href="https://professorcam.github.io/pcap/">https://professorcam.github.io/pcap/</a> and click a few rows. Stop the capture.',
        'Edit, Preferences, Protocols, TLS, <i>(Pre)-Master-Secret log filename</i> = your keylog.txt. Filter on <code>http</code>: your requests for <code>/pcap/</code>, <code>style.css</code>, the pcap files.',
        'Now try the same capture on a friend\'s laptop without the key log. Nothing. The secrets only exist at the two ends.'
      ] },
      { h: 'What TLS 1.3 looks like', p: {
        s: [
          'The modern greeting is shorter and hides more. The browser sends its half of the secret in the very first message, so the server can answer and start scrambling straight away. Only the two hellos are readable; even the certificate is hidden.',
          'The notebook now has five lines per connection instead of one: separate secrets for the greeting and for the real data, in each direction.'
        ],
        m: [
          'The handshake is shorter and hides more. The Client Hello (frame 12) already contains a key share, so the server can answer with its own key share in the Server Hello (frame 14) and immediately switch to encryption: the certificate, the signature and Finished all arrive as "Application Data". Only the two Hellos are readable. One round trip instead of two.',
          'The key log has five lines per connection instead of one: separate secrets for the handshake and for the application data, in each direction. Wireshark and this page use CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET to open the rest of the handshake and CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0 for the HTTP.'
        ],
        e: [
          'The ClientHello (frame 12) carries key_share, so the ServerHello (frame 14) returns the server share and everything after it is encrypted under the handshake traffic keys: EncryptedExtensions, Certificate, CertificateVerify and Finished all appear on the wire as content type 23, "Application Data". Only the two Hellos are cleartext. 1-RTT instead of 2.',
          'The key log has five lines per connection: CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 and EXPORTER_SECRET. The handshake secrets open the rest of the handshake; the _0 traffic secrets open the HTTP.'
        ]
      }, keylog: 'keys/github-pages-keylog.txt', keylogLines: 5 },
      { h: 'A recorded visit, decrypted here', p: [{
        s: 'This capture is a real browser visit to the Protocols site with the notebook switched on. The page below unscrambles it right here. The web pages were squashed (compressed) on the wire and are unpacked so you can read them.',
        m: 'This capture is a real Chromium visit to the Protocols site with the key log switched on. The page below decrypts it the TLS 1.3 way: HKDF-Expand-Label derives an AES key and IV from each traffic secret, the nonce is the IV XOR the record number, and the real content type is the last byte inside each decrypted record. The responses were gzip-compressed on the wire and are unpacked here so you can read them.',
        e: 'A real Chromium visit to the Protocols site with SSLKEYLOGFILE set. Decryption below follows RFC 8446 section 7.3: HKDF-Expand-Label (HKDF, RFC 5869) derives key and IV from each traffic secret, the per-record nonce is the IV XOR the 64-bit record sequence number, and the true content type is the last non-zero byte of the decrypted plaintext. Responses were Content-Encoding: gzip and are inflated for display.'
      }], decrypt: { file: FILES.pages, keylog: 'keys/github-pages-keylog.txt', highlight: 'GET /pcap[^ ]*' } }
    ],
    actors: [{ name: 'Chromium', addr: '172.17.0.2' }, { name: 'GitHub Pages', addr: '185.199.109.153 : 443' }],
    steps: [
      { from: 0, to: 1, label: 'DNS: A professorcam.github.io?  (frames 1 to 8, four answers)' },
      { from: 0, to: 1, label: 'Client Hello: SNI professorcam.github.io, key share x25519  (frame 12)' },
      { from: 1, to: 0, label: 'Server Hello: TLS 1.3, TLS_AES_128_GCM_SHA256, key share  (frame 14)' },
      { from: 1, to: 0, label: '{Encrypted Extensions, Certificate, Certificate Verify, Finished}  (frames 14, 16)', dashed: true },
      { from: 0, to: 1, label: '{Finished}  (frame 18)', dashed: true },
      { from: 0, to: 1, label: '{GET /pcap/ HTTP/1.1}  (frame 19)', dashed: true },
      { from: 1, to: 0, label: '{HTTP/1.1 200 OK, gzip}  (frame 22)', dashed: true },
      { from: 0, to: 1, label: '{GET /pcap/style.css}, then the scripts on three more connections', dashed: true }
    ],
    lookFor: [
      { s: 'Frames 1 to 8: the browser first asked where the website lives. That question and its answer are not scrambled at all.',
        m: 'Frames 1 to 8: the browser asked two DNS servers for A and AAAA records and got four IPv4 addresses for GitHub Pages. DNS is still in the clear.',
        e: 'Frames 1 to 8: A and AAAA queries to two resolvers, four A records returned for professorcam.github.io. Plain DNS on port 53 is cleartext.' },
      { s: 'Frame 12: the browser\'s hello names the website it wants. Anyone on the path can see you went to professorcam.github.io; they cannot see which page.',
        m: 'Frame 12: the Client Hello names the site in the SNI extension. Anyone on the path knows you went to professorcam.github.io; they do not know which page.',
        e: 'Frame 12: ClientHello with server_name = professorcam.github.io (SNI, cleartext). The path is inside the encrypted request; the hostname is not.' },
      { s: 'Frame 14: after the server\'s hello come two chunks labelled "Application Data". They are not data at all; they are the hidden certificate and the end of the greeting.',
        m: 'Frame 14: Server Hello, then Change Cipher Spec, then "Application Data" 42 bytes and 4,169 bytes. Those are not application data at all; they are the encrypted certificate and Finished. TLS 1.3 disguises its handshake.',
        e: 'Frame 14: ServerHello, a compatibility ChangeCipherSpec, then records of 42 and 4,169 bytes typed as Application Data: the encrypted EncryptedExtensions, Certificate, CertificateVerify and Finished.' },
      { s: 'Frame 19: the request for the page. Unscrambled below, you can even see which browser asked.',
        m: 'Frame 19, 727 bytes: GET /pcap/ HTTP/1.1. The decrypted view below shows the request headers, including the User-Agent that says HeadlessChrome.',
        e: 'Frame 19, 727 bytes: GET /pcap/ HTTP/1.1. The decrypted headers include User-Agent: HeadlessChrome.' },
      { s: 'Frame 22: the page came back squashed (compressed) to save space. Squashing has to happen before scrambling, because scrambled data cannot be squashed.',
        m: 'Frame 22: HTTP/1.1 200 OK with Content-Encoding: gzip. Encrypted data is incompressible, so compression has to happen before TLS.',
        e: 'Frame 22: HTTP/1.1 200 OK, Content-Encoding: gzip. Ciphertext is incompressible, so compression is applied at the HTTP layer before TLS.' },
      { s: 'The browser opened nine connections for one page. Three of them were opened just in case and never used.',
        m: 'Chromium opened nine connections for one page load. Three of them (ports 38456, 38466, 38476) are SYN only: pre-connects it never used.',
        e: 'Nine connections for one page load; ports 38456, 38466 and 38476 are SYN-only pre-connects that were never used.' },
      { s: 'One connection has no line in the notebook, so neither this page nor Wireshark can open it. The file only helps for what it recorded.',
        m: 'Connection 38448 has no matching line in the key log, so the page cannot open it and neither can Wireshark. A key log only helps for the connections it actually covers.',
        e: 'Connection 38448 has no key-log entry, so neither this page nor Wireshark can decrypt it. Coverage is per connection.' }
    ]
  }
];
