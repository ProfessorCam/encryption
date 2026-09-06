# HTTPS + Wireshark Decryption Lab

A follow-up to the HTTP sniffing demo. The same Tux login page, now served over
**HTTPS**. Students capture their own form submission in Wireshark, see only
ciphertext, then use the keys the page hands them to decrypt the traffic and
recover the password they typed.

The page teaches the two-layer key model:

- **Asymmetric** (RSA public/private keypair) — sets up the session.
- **Symmetric** (per-session secrets, in NSS key-log format) — encrypts the data.

The server intentionally uses **TLS 1.2 with RSA key-exchange ciphers (no
forward secrecy)** so that *either* the private key *or* the session-secret log
is enough to decrypt a capture — letting students try both Wireshark methods.

> ⚠️ For classroom use only. Showing a private key and disabling forward secrecy
> is deliberately insecure — the opposite of what you'd do in production.

The page uses the same theme and site menu as the Protocols site
(<https://professorcam.github.io/pcap/>). Unlike that site it cannot be hosted on
GitHub Pages: the whole point is a TLS server whose private key and per-session
secrets are handed to students, and Pages terminates TLS with its own keys.

## Build & run

```bash
docker build -t https-demo .
docker run --rm -p 8443:443 https-demo
```

Open **https://localhost:8443** and accept the self-signed-certificate warning
(itself a teaching moment: browsers don't trust certs nobody vouched for). The
browser may also flag "obsolete cryptography" — that's the deliberately old
RSA/TLS 1.2 cipher, another thing to point out. If a very new browser refuses to
connect at all, use Firefox or `curl -k` to submit the form.

## Endpoints

| Path                | Purpose                                             |
|---------------------|-----------------------------------------------------|
| `/`                 | Login page + live public key, private key, key log  |
| `/action_page.php`  | Form target (GET) — confirmation page               |
| `/server.key`       | RSA private key (for Wireshark RSA keys list)       |
| `/server.crt`       | Self-signed certificate                             |
| `/keylog.txt`       | Session secrets (for Wireshark master-secret log)   |

## Student worksheet

1. Start **Wireshark** and capture on your **loopback** interface (`lo` /
   "Adapter for loopback"). Set the display filter to `tls`.
2. In the browser, go to `https://localhost:8443`, type a password, and Submit.
3. Stop the capture. Notice the `Application Data` packets are unreadable.
4. Back on the page (refresh it), download **`keylog.txt`** and load it in
   Wireshark: Preferences → Protocols → TLS → **(Pre)-Master-Secret log
   filename** → point at the file. *(This method works on every Wireshark
   build.)*
5. The TLS packets now decode as HTTP. Right-click the request → **Follow → HTTP
   Stream** and find your password:
   `GET /action_page.php?name=Tux&pwd=YOURPASSWORD`

### Optional / advanced: decrypt with the RSA private key

Because this server disables forward secrecy, the asymmetric **private key**
alone can — in principle — decrypt the whole capture: download `server.key` and
add it under Preferences → Protocols → TLS → **RSA keys list** (IP `any`, Port
`443`, Protocol `http`). Good for illustrating what "no forward secrecy" means.
Note that **many recent Wireshark builds cannot do raw-RSA decryption** (their
GnuTLS backend dropped the primitive, failing with *"No certificate was
found"*). If it doesn't work, that's expected — use the keylog method above.

## Command-line proof (optional, for instructors)

```bash
# capture while submitting
tshark -i lo -w /tmp/cap.pcap &
curl -k "https://localhost:8443/action_page.php?name=Tux&pwd=test123"
kill %1

# decrypt with the exported session secrets (grab the log AFTER submitting)
docker cp <container>:/certs/keylog.txt .
tshark -r /tmp/cap.pcap -o tls.keylog_file:$(pwd)/keylog.txt \
  -Y http.request -T fields -e http.request.full_uri
# -> GET https://localhost:8443/action_page.php?name=Tux&pwd=test123
```

## The static companion site (GitHub Pages)

`site/` is a second, purely static version of this lesson that lives at
<https://professorcam.github.io/encryption/> and needs no server at all. It has the same theme and
site menu as the Protocols site and is published by `.github/workflows/pages.yml` on every push to
`main`. It does not replace the container; it records what the container does so students can
study it without running anything:

- `site/pcaps/https-login-192.168.110.1.pcap`: a real Chrome login to this container (run on a
  Docker network numbered like the lab, 192.168.110.0/23), captured with tcpdump next to the
  server. 69 packets, TLS 1.2 with the RSA key exchange.
- `site/keys/keylog.txt`, `server.key`, `server.crt`: what the container handed out during that
  session, plus `chrome-keylog.txt`, the lines Chrome itself wrote with `--ssl-key-log-file`.
- `site/pcaps/https-github-pages.pcap` and `site/keys/github-pages-keylog.txt`: a real Chromium
  visit to the Protocols site on GitHub Pages, TLS 1.3, decryptable only through the browser's key
  log (the SSLKEYLOGFILE method).
- `site/tls.js` decrypts both captures in the browser with WebCrypto (TLS 1.2 PRF and AES-GCM, and
  the TLS 1.3 HKDF schedule), so the page can show the recovered HTTP next to the ciphertext, and
  show every record failing when one hex digit of the key is changed.

To re-record the login capture: start the container on a network with the lab's addressing, run
tcpdump in a container that shares its network namespace, drive Chrome with
`--ignore-certificate-errors --ssl-key-log-file=...`, then copy `/certs/keylog.txt`, `server.key`
and `server.crt` out of the container.
