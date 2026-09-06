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
  http: 'http-httpforever.pcap'          /* the plain HTTP capture from row 6 of the Protocols site */
};

var LESSONS = [
  {
    id: 'https',
    title: 'HTTPS',
    subtitle: 'What a sniffer sees',
    oneLiner: 'HTTPS is ordinary HTTP wrapped in TLS: the same requests and responses, scrambled so that only the two ends can read them.',
    layer: 'TLS sits between TCP (layer 4) and HTTP (layer 7). Everything below it stays visible.',
    command: 'Chrome opened https://192.168.110.1/ and submitted the login form; tcpdump -i eth0 port 443 was running on the server',
    file: FILES.login,
    sections: [
      { h: 'Why HTTP was not enough', p: [
        'On the Protocols site, row 6 showed a plain HTTP request. Every header, every form field and the whole page came past in readable text. Anyone on the same Wi-Fi with Wireshark could read it, and so could every router between you and the server. Here is that packet again, frame 6 of the plain HTTP capture, with the bytes it carried:'
      ], packet: { file: FILES.http, no: 6 }, after: [
        'HTTPS fixes that by putting <b>TLS</b> (Transport Layer Security) between TCP and HTTP. TCP still delivers the bytes in order, HTTP still says <code>GET /</code>, but in between the bytes are encrypted. The padlock in the address bar means exactly this and nothing more: the conversation is scrambled, and the certificate said the server is who it claims to be.'
      ] },
      { h: 'Two kinds of keys', p: [
        'Encryption needs a key, and the two sides have to agree on one without anyone listening in being able to work it out. TLS uses two kinds of keys to solve that:',
        '<b>Asymmetric (public / private).</b> The server has a pair. The public key is in its certificate and is handed to everyone. Whatever is encrypted with the public key can only be opened with the private key, which never leaves the server. That is how the two sides agree on a secret in front of an audience.',
        '<b>Symmetric (the session key).</b> Once both sides share a secret, they derive a session key from it and use fast symmetric encryption (AES) for all the actual data. Same key both ways, a fresh one for every connection.',
        'So: asymmetric to set up, symmetric to talk. The rest of this site is about where those keys are and what you can do with them.'
      ] },
      { h: 'One encrypted packet, built up', p: [
        'Frame 49 in the capture below carries the login form. Here is how the browser built it. Watch what is still readable when it reaches the wire.'
      ], anim: 'tls-record' },
      { h: 'What is still visible, and what is hidden', p: [
        'Encryption starts above TCP, so a sniffer still sees: both IP addresses, both ports (443 tells them it is HTTPS), how many bytes went each way and when, the name of the site the browser asked for (the SNI field of the Client Hello) and the server\'s certificate. Traffic analysis alone tells you a lot.',
        'What it cannot see: the URL path, the query string with the password, headers, cookies, and the page that came back. Those are inside the Application Data records, and without a key they are noise.'
      ] }
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
      'Frames 1 to 3: a normal TCP handshake to port 443. Nothing about TLS changes TCP.',
      'Frame 4, Client Hello: open it. 16 cipher suites offered, the client random, and no server name because the site was addressed by IP. This is the only place the browser says what it can do.',
      'Frame 6: the server picks RSA-AES128-GCM-SHA256 and sends its certificate in the clear. Certificates are public; that is the point of them.',
      'Frame 8: Client Key Exchange, 258 bytes. A secret encrypted with the public key from the certificate. Then Change Cipher Spec, and the very next message is already unreadable.',
      'Frame 15, Application Data, 754 bytes: that is GET / HTTP/1.1 with all its headers. Compare with row 6 on the Protocols site where the same request was readable.',
      'Frame 49: the login form. The URL with the password is in there. 771 bytes of TLS, and not one readable character.',
      'The browser opened four connections (ports 46484, 46500, 46516, 46522). Chrome does that to be quick; connections 3 and 4 use a shorter handshake, explained in row 2.'
    ]
  },

  {
    id: 'handshake',
    title: 'The TLS handshake',
    subtitle: 'From Client Hello to Finished',
    oneLiner: 'Before a single byte of HTTP is sent, the two sides agree on a version, a cipher, and a secret, in four packets that are mostly readable.',
    layer: 'TLS handshake messages ride inside TLS records, inside TCP. Frames 4, 6, 8 and 14 are the whole thing.',
    command: 'Same capture as row 1; look at the first connection, client port 46484',
    file: FILES.login,
    sections: [
      { h: 'Step by step', p: [
        '<b>Client Hello (frame 4).</b> The browser lists the TLS versions and cipher suites it supports, sends 32 random bytes (the <i>client random</i>) and, for TLS 1.3, its half of a key exchange in advance. Chrome also throws in deliberate junk values called GREASE so servers never learn to rely on a fixed list.',
        '<b>Server Hello, Certificate, Server Hello Done (frame 6).</b> The server picks one version and one cipher suite from the list, sends its own 32 random bytes, and its certificate. The certificate carries the public key and is sent in the clear.',
        '<b>Client Key Exchange (frame 8).</b> With the RSA cipher chosen here, the browser makes a 48-byte <i>pre-master secret</i>, encrypts it with the server\'s public key and sends it. Only the private key can open it. Both sides now mix pre-master secret + client random + server random into the <i>master secret</i>, and derive the session keys from that.',
        '<b>Change Cipher Spec and Finished (frames 8 and 14).</b> Each side announces "from here on I am encrypting" and sends a Finished message, encrypted with the new keys, containing a hash of everything said so far. If the hashes agree, nobody tampered with the handshake. The next record is HTTP.'
      ] },
      { h: 'Why this lab uses the RSA key exchange', p: [
        'The server was set up on purpose to offer only <b>RSA key exchange</b> ciphers and only TLS 1.2. With those, the whole secret is decided by the client and sent encrypted under the server\'s public key. Whoever holds the private key can decrypt the Client Key Exchange, recover the pre-master secret, and derive the same session keys: that is how Wireshark\'s "RSA keys list" method works, and it is what you will do in row 4.',
        'Real websites stopped doing this years ago. Modern TLS uses ephemeral Diffie-Hellman (the ECDHE ciphers and all of TLS 1.3): each side sends a throwaway public value, both compute the same secret, and the secret is never on the wire at all, not even encrypted. That property is called <b>forward secrecy</b>: even if the server\'s private key leaks next year, last year\'s captures stay unreadable. Chrome offered those ciphers first in frame 4; look at the order of the list.'
      ] },
      { h: 'The short handshake: resumption', p: [
        'Connections 3 and 4 (client ports 46516 and 46522) look different: Client Hello, then a Server Hello with Change Cipher Spec and Finished straight away, and no Certificate or Client Key Exchange. The browser presented the session ID from connection 1, the server still remembered the master secret, and they skipped the expensive part. Two packets fewer, and no public-key maths.'
      ] }
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
      'Frame 4: expand the Client Hello. The cipher list begins with GREASE, then the three TLS 1.3 suites, then ECDHE, and the RSA ones last. Chrome offers the RSA key exchange only as a last resort.',
      'Frame 6: the Server Hello picks the second-to-last kind on that list. Also in frame 6: a Certificate of 815 bytes, readable by anyone.',
      'Frame 8: 258 bytes of Client Key Exchange (256 bytes is the RSA-2048 ciphertext plus a 2-byte length), immediately followed by Change Cipher Spec and one Encrypted Handshake Message: the Finished.',
      'Frame 14: the server\'s answer, in the same order. After this frame there is no more readable TLS in this connection.',
      'Frames 44, 46, 48: connection 3. Client Hello, then Server Hello + Change Cipher Spec + Finished in one 207-byte packet. That is session resumption.',
      'Notice the timing: from SYN (frame 1) to the first HTTP request (frame 15) took 12 milliseconds. On a real network the handshake costs one or two round trips before any page can load.'
    ]
  },

  {
    id: 'keys',
    title: 'The keys',
    subtitle: 'Public, private, and the key log',
    oneLiner: 'Three files can open this capture: the server\'s private key, the key log the server wrote, and the key log the browser wrote. They all lead to the same session key.',
    layer: 'Nothing in this row is a packet. These are the files the two ends kept.',
    command: 'openssl req -x509 -newkey rsa:2048 ... on the server; SSLKEYLOGFILE and Python\'s ssl.SSLContext.keylog_filename on the two ends',
    sections: [
      { h: 'The certificate and its public key', p: [
        'The server made itself a certificate when it started: a 2048-bit RSA key pair, with the public half wrapped in a certificate for the name <code>localhost</code>, signed by nobody but itself. That is why a browser shows a warning for it: the key is fine, but no authority vouched that it belongs to whoever answers at that address. Real sites get their certificate signed by an authority the browser already trusts.',
        'Frame 6 of the capture carries exactly this file. You could copy the bytes out of the packet and get the same certificate.'
      ], keylog: 'keys/server.crt' },
      { h: 'The private key', p: [
        'This is the file that must never leave a real server. Here it is, on purpose, because the lab is about seeing what it can do. With the RSA key exchange it decrypts the Client Key Exchange in frame 8, and from there everything. Wireshark takes it under <i>Preferences, Protocols, TLS, RSA keys list</i>.',
        'On the modern web this file would be useless to an eavesdropper: with TLS 1.3 and ECDHE the secret is never encrypted with it. Row 5 shows that with a real site.'
      ], files: [{ label: 'server.key', href: 'keys/server.key', note: 'RSA private key, PEM' }, { label: 'server.crt', href: 'keys/server.crt', note: 'the certificate' }] },
      { h: 'The key log', p: [
        'Both ends of a TLS connection know the session secrets, so both can write them down. The format is one line per connection: a label, the 32-byte client random from the Client Hello, and the secret. Wireshark matches lines to connections by the client random, which is in the capture in the clear.',
        'The server wrote this file while the capture was being made. Four lines, one per connection; connections 2, 3 and 4 share the master secret of connection 1 because of resumption:'
      ], keylog: 'keys/keylog.txt', after: [
        'Chrome, started with <code>--ssl-key-log-file</code>, wrote its own file at the same time. Filter it to the lines for this server and it is identical, because both sides computed the same secrets. That is the whole idea of TLS. Row 5 uses this browser-side trick against a real site.'
      ], files: [{ label: 'keylog.txt', href: 'keys/keylog.txt', note: 'written by the server' }, { label: 'chrome-keylog.txt', href: 'keys/chrome-keylog.txt', note: 'written by the browser, same lines' }] },
      { h: 'Which key opens what', p: [], table: [
        ['', 'Private key (server.key)', 'Key log (keylog.txt)'],
        ['Who has it', 'Only the server', 'Whichever end wrote it: the server, or the browser'],
        ['Opens TLS 1.2 with RSA key exchange (this lab)', 'Yes', 'Yes'],
        ['Opens TLS 1.2 with ECDHE, or TLS 1.3 (the real web)', 'No: the secret was never encrypted with it', 'Yes'],
        ['Works after the connection is over', 'Yes, on any old capture', 'Only for connections logged at the time'],
        ['Wireshark setting', 'TLS, RSA keys list', 'TLS, (Pre)-Master-Secret log filename']
      ] }
    ],
    lookFor: [
      'The key log labels: CLIENT_RANDOM lines are TLS 1.2. TLS 1.3 uses several secrets per connection (CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0 and so on). Row 5 shows those.',
      'The second field of every key log line is a client random. Find the same 64 hex characters in the Client Hello of frame 4.',
      'A PEM file is just base64 between BEGIN and END lines. The private key is 1704 characters; the certificate is 1151.'
    ]
  },

  {
    id: 'decrypt',
    title: 'Decrypt the recorded session',
    subtitle: 'In Wireshark, and right here',
    oneLiner: 'Give Wireshark the key log or the private key and the Application Data becomes HTTP again, password included.',
    layer: 'This is the capture from row 1, decrypted. Nothing in the packets changes; only your ability to read them does.',
    command: 'Wireshark: Edit, Preferences, Protocols, TLS. Then Follow, HTTP Stream.',
    file: FILES.login,
    downloads: [{ label: 'keylog.txt', href: 'keys/keylog.txt' }, { label: 'server.key', href: 'keys/server.key' }],
    sections: [
      { h: 'Method 1: the key log (works on every Wireshark)', p: [
        'This is the method real analysts use, and it works for any TLS version.'
      ], steps: [
        'Download the capture and <code>keylog.txt</code> with the buttons at the bottom of this page.',
        'Open the capture in Wireshark. Type <code>tls</code> in the display filter: everything after frame 14 is Application Data, unreadable.',
        'Edit, Preferences, Protocols, TLS. In <i>(Pre)-Master-Secret log filename</i> choose <code>keylog.txt</code>. OK.',
        'The Protocol column now says HTTP for frames 15, 20, 33, 34, 49 and 54. Right-click frame 49, Follow, HTTP Stream.',
        'Read the request line: <code>GET /action_page.php?name=Tux&amp;pwd=Penguin2026%21</code>. The <code>%21</code> is an exclamation mark, URL-encoded.'
      ] },
      { h: 'Method 2: the private key (RSA key exchange only)', p: [
        'Same result by a different door. This only works because the server chose an RSA key-exchange cipher, and some Wireshark builds have this feature switched off, so use Method 1 if it does nothing.'
      ], steps: [
        'Download <code>server.key</code>.',
        'Edit, Preferences, Protocols, TLS, <i>RSA keys list</i>, Edit. Add a row: key file = server.key, leave IP, port and protocol empty. OK twice.',
        'Wireshark decrypts frame 8 with the private key, recovers the pre-master secret, and derives the same session keys. Everything decodes exactly as before.',
        'Remove the key again, and the same frames go back to Application Data. Nothing changed but your key.'
      ] },
      { h: 'Do it live instead of from the recording', p: [
        'The recording is convenient, but the server that made it is on Docker Hub, so you can capture your own login instead. Run it on your machine, capture on the loopback interface, and every file the steps above need is handed to you by the page itself:'
      ], steps: [
        '<code>docker run -d --name https-demo -p ' + SITE.port + ':443 ' + SITE.image + '</code>',
        'Start Wireshark on the loopback interface (<i>lo</i>, or "Adapter for loopback"), filter <code>tls</code>.',
        'Open <a href="https://localhost:' + SITE.port + '/">https://localhost:' + SITE.port + '/</a>, accept the certificate warning (a fresh self-signed key is generated every time the container starts), type a password, Submit.',
        'The confirmation page links to <code>keylog.txt</code> and <code>server.key</code> for your own session. Load either one in Wireshark exactly as above and find your password.',
        'Finished: <code>docker rm -f https-demo</code>.'
      ] },
      { h: 'The same thing, done in your browser', p: [
        'To prove there is no trick, this page does what Wireshark does, in JavaScript: it reassembles the TCP streams from the packets below, takes the master secret from <code>keylog.txt</code>, derives the AES session keys with the TLS 1.2 key expansion, and opens every record with AES-GCM using the browser\'s own crypto. The result is below. Flip to the wrong key and watch every record fail its integrity check.'
      ], decrypt: { file: FILES.login, keylog: 'keys/keylog.txt', highlight: 'pwd=[^ &\\s]+' } }
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
      'Before the keys: frame 49 is "Application Data", 837 bytes. After: "GET /action_page.php?name=Tux&pwd=Penguin2026%21 HTTP/1.1". Same bytes on disk.',
      'The password went over the wire in the URL because the form used GET. HTTPS hid it from the network, but it is still in the server log and the browser history. Encryption is not the same as privacy.',
      'The 200 OK in frame 20 says HTTP/1.0 and Server: HTTPSDemo/1.0. Headers are hidden by TLS too; you only see them because you have the key.',
      'Frames 21, 23, 24: one TLS record of 16,408 bytes, the maximum allowed, split across three TCP segments. Wireshark reassembles them before decrypting; so does this page.',
      'Wrong key: with one hex digit of the master secret changed, AES-GCM refuses every record. It does not produce garbage, it produces nothing. That is the integrity tag doing its job.'
    ]
  },

  {
    id: 'yourbrowser',
    title: 'Decrypt your own browser',
    subtitle: 'SSLKEYLOGFILE against a real site',
    oneLiner: 'Your browser will write its session secrets to a file if you ask. With that file, Wireshark decrypts your own traffic to any HTTPS site, including this one.',
    layer: 'TLS 1.3 to a real server on the internet. No private key involved, and none would help.',
    command: 'chromium --ssl-key-log-file=keylog.txt --disable-http2 https://professorcam.github.io/pcap/  with tcpdump port 53 or port 443 alongside',
    file: FILES.pages,
    downloads: [{ label: 'github-pages-keylog.txt', href: 'keys/github-pages-keylog.txt' }],
    sections: [
      { h: 'Why the private-key trick does not work out there', p: [
        'GitHub Pages, like every modern site, speaks TLS 1.3. The secret comes from an ephemeral Diffie-Hellman exchange (x25519 in this capture): each side sends a throwaway public value and both compute the shared secret; it is never transmitted. GitHub\'s private key only signs the handshake to prove identity. Even GitHub cannot decrypt a recording of your visit afterwards.',
        'But the endpoints still know the secrets, and one of the endpoints is your browser. Chrome, Edge, Brave and Firefox all honour an environment variable named <code>SSLKEYLOGFILE</code>: set it before the browser starts and every connection\'s secrets are appended to that file in the same format as row 3. Wireshark reads it directly.'
      ] },
      { h: 'Do it yourself', p: [
        'Close the browser completely first; it only reads the variable at startup. Chromebooks and managed school laptops will usually not allow this, which is what the recorded session further down is for.'
      ], steps: [
        '<b>Windows:</b> Settings, System, About, Advanced system settings, Environment Variables. Add a user variable <code>SSLKEYLOGFILE</code> with value <code>C:\\Users\\you\\keylog.txt</code>. Or in PowerShell: <code>$env:SSLKEYLOGFILE="$HOME\\keylog.txt"; &amp; "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"</code>',
        '<b>macOS:</b> in Terminal: <code>SSLKEYLOGFILE=$HOME/keylog.txt open -a "Google Chrome"</code>  (or Firefox).',
        '<b>Linux:</b> <code>SSLKEYLOGFILE=$HOME/keylog.txt google-chrome</code>  or  <code>SSLKEYLOGFILE=$HOME/keylog.txt firefox</code>.',
        'Start Wireshark, capture on your Wi-Fi interface, display filter <code>tls</code>.',
        'In the browser, open <a href="https://professorcam.github.io/pcap/">https://professorcam.github.io/pcap/</a> and click a few rows. Stop the capture.',
        'Edit, Preferences, Protocols, TLS, <i>(Pre)-Master-Secret log filename</i> = your keylog.txt. Filter on <code>http</code>: your requests for <code>/pcap/</code>, <code>style.css</code>, the pcap files.',
        'Now try the same capture on a friend\'s laptop without the key log. Nothing. The secrets only exist at the two ends.'
      ] },
      { h: 'What TLS 1.3 looks like', p: [
        'The handshake is shorter and hides more. The Client Hello (frame 12) already contains a key share, so the server can answer with its own key share in the Server Hello (frame 14) and immediately switch to encryption: the certificate, the signature and Finished all arrive as "Application Data". Only the two Hellos are readable. One round trip instead of two.',
        'The key log has five lines per connection instead of one: separate secrets for the handshake and for the application data, in each direction. Wireshark and this page use CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET to open the rest of the handshake and CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0 for the HTTP.'
      ], keylog: 'keys/github-pages-keylog.txt', keylogLines: 5 },
      { h: 'A recorded visit, decrypted here', p: [
        'This capture is a real Chromium visit to the Protocols site with the key log switched on. The page below decrypts it the TLS 1.3 way: HKDF-Expand-Label derives an AES key and IV from each traffic secret, the nonce is the IV XOR the record number, and the real content type is the last byte inside each decrypted record. The responses were gzip-compressed on the wire and are unpacked here so you can read them.'
      ], decrypt: { file: FILES.pages, keylog: 'keys/github-pages-keylog.txt', highlight: 'GET /pcap[^ ]*' } }
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
      'Frames 1 to 8: the browser asked two DNS servers for A and AAAA records and got four IPv4 addresses for GitHub Pages. DNS is still in the clear.',
      'Frame 12: the Client Hello names the site in the SNI extension. Anyone on the path knows you went to professorcam.github.io; they do not know which page.',
      'Frame 14: Server Hello, then Change Cipher Spec, then "Application Data" 42 bytes and 4,169 bytes. Those are not application data at all; they are the encrypted certificate and Finished. TLS 1.3 disguises its handshake.',
      'Frame 19, 727 bytes: GET /pcap/ HTTP/1.1. The decrypted view below shows the request headers, including the User-Agent that says HeadlessChrome.',
      'Frame 22: HTTP/1.1 200 OK with Content-Encoding: gzip. Encrypted data is incompressible, so compression has to happen before TLS.',
      'Chromium opened nine connections for one page load. Three of them (ports 38456, 38466, 38476) are SYN only: pre-connects it never used.',
      'Connection 38448 has no matching line in the key log, so the page cannot open it and neither can Wireshark. A key log only helps for the connections it actually covers.'
    ]
  }
];
