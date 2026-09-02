# TLS when a certificate authority will not issue to you

An island needs TLS, and until now that meant a certificate from Let's
Encrypt, which meant a domain, port 80 open to the world, and an authority
willing to issue to your address. Any of the three can go away; an operator in
Russia asked what happens to an island the day Let's Encrypt stops issuing
there.

Three answers, in the order to try them. The first two keep a normal
certificate that every client, a browser included, verifies as before. The
third does without a certificate authority altogether, and is the one built
for a network that expects to be walled off.

| | you need | who can connect | what changes for users |
|---|---|---|---|
| 1. DNS-01 | a domain at a provider with an API | everyone, browser included | nothing |
| 2. Another CA | a domain | everyone, browser included | nothing |
| 3. Fingerprint | an IP address | Android, iOS, desktop, CLI | they compare a fingerprint once |

## 1. Keep Let's Encrypt, validate over DNS

Let's Encrypt proves you control a name either by fetching a file from port
80 (HTTP-01, the default) or by reading a TXT record from your DNS (DNS-01).
The second works when port 80 is closed, when the authority's validators
cannot reach the host at all, or when the host is not the machine the name
points at. It does not help when the authority refuses the name itself; that
is answer 2.

Caddy talks to the DNS provider through a module the stock image does not
carry, so the island builds its own:

1. Get an API token from the provider, scoped to the one zone. The bundled
   image speaks Cloudflare, deSEC and Hetzner (each has a free tier);
   `deploy/Dockerfile.caddy-dns` shows where another module goes.
2. Put the token in `.env` and switch the stack to the override, permanently:

   ```ini
   CF_API_TOKEN=...            # or DESEC_TOKEN, HETZNER_API_TOKEN
   COMPOSE_FILE=docker-compose.yml:docker-compose.dns.yml
   ```

   ⚠ The `COMPOSE_FILE` line is what keeps a plain `docker compose up -d`,
   and `deploy/rcq-update.sh`, on the built image. Without it they put the
   stock image back without a word, and the next renewal fails.
3. In `deploy/Caddyfile.compose`, uncomment the `tls { dns ... }` block in
   the site and name your provider:

   ```caddyfile
   tls {
   	dns cloudflare {env.CF_API_TOKEN}
   }
   ```

   (`dns desec {env.DESEC_TOKEN}` and `dns hetzner {env.HETZNER_API_TOKEN}`
   for the other two.)
4. Build and restart: `docker compose up -d --build caddy`, then
   `docker compose logs -f caddy` until the certificate is obtained.

⚠ The image build pulls Go modules through `proxy.golang.org`. On a network
where that is filtered, build the image elsewhere and carry it over with
`docker save` / `docker load`, or pass a mirror with `--build-arg GOPROXY=...`
(the Dockerfile says how).

## 2. Another certificate authority

Any ACME authority works with the same Caddy. What differs between them is
whether they hand out accounts freely:

* **Buypass** (Norway) issues free 180-day certificates over ACME with nothing
  but a contact email. The block in `deploy/Caddyfile.compose` is ready to
  uncomment:

  ```caddyfile
  cert_issuer acme
  cert_issuer acme {
  	dir https://api.buypass.com/acme/directory
  	email you@example.com
  }
  ```

  Two issuers means Caddy tries them in that order for every certificate and
  renewal: Let's Encrypt as long as it works, Buypass the day it does not,
  without anybody editing anything at three in the morning. Buypass validates
  over HTTP-01 and DNS-01 only. To combine with answer 1, put the `dns` line
  inside each `issuer acme { }` of the site's `tls` block instead of using
  the global option.

* **ZeroSSL** and **Google Trust Services** issue over ACME too, but only to
  an account created with them first, bound to the ACME client through
  External Account Binding: a key id and an HMAC key from your account page,
  given to Caddy as

  ```caddyfile
  cert_issuer acme {
  	dir https://acme.zerossl.com/v2/DV90
  	email you@example.com
  	eab <key_id> <hmac_key>
  }
  ```

  (`https://dv.acme-v02.api.pki.goog/directory` for Google. Caddy's own
  `zerossl` issuer can fetch the EAB from a ZeroSSL API key instead:
  `cert_issuer zerossl <api_key>`.)

⚠ A certificate authority is a policy, not a protocol. Whether any of these
issues to an address in a given country is their decision and can change; the
only answer that does not depend on one is the third.

## 3. No certificate authority: fingerprint mode

The island serves a certificate it made itself, and the RCQ apps trust it the
way SSH trusts a host key: by its fingerprint, not by who signed it. Nothing
outside the island and its users is involved, and nothing outside can revoke
it. A domain becomes optional; an island reachable only by IP is a normal
island in this mode.

### What it is

`install.sh` asks "Do you have a domain name pointing at this host?" (on a
terminal; piped from `curl` it cannot ask and wants `RCQ_TLS=fingerprint` said
in the environment) and on "no" (or with `RCQ_TLS=fingerprint`, with or without
`RCQ_DOMAIN`) it:

* issues `certs/island.key` (EC P-256) and `certs/island.crt`, self-signed
  for ten years, with the address in the subject alternative names: the
  public IP, plus the name when you gave one. The IP is what a lookup service
  sees, or `RCQ_ADDRESS` on a box behind 1:1 NAT or where the lookup is
  blocked; never the box's own interface address, which on 1:1 NAT is a
  private one. A private address is refused unless `RCQ_FORCE=1` says a LAN
  or a VPN is the point;
* writes `RCQ_TLS_MODE=fingerprint`,
  `RCQ_CADDYFILE=./deploy/Caddyfile.fingerprint.compose` and
  `RCQ_DOMAIN=<address>` to `.env`;
* brings the stack up with `deploy/Caddyfile.fingerprint.compose`: the same
  proxy and log masking as the normal file, `auto_https off`, the island's
  own certificate on `:443`, and a `:80` that answers 404 so the port is not
  a door left open;
* prints the fingerprint and the line to hand out, then checks that the wire
  presents exactly that certificate:

  ```
  Give your users: 203.0.113.5#ab12cd34…
  ```

  With a name whose A-record does not point at the host yet, the line carries
  the IP (the certificate covers it too) and says to hand out the name form
  once DNS is live. An IPv6 literal is written in brackets, `[2001:db8::1]#…`,
  the form the apps key their trust on.

The fingerprint is SHA-256 over the certificate, the same number
`openssl x509 -noout -fingerprint -sha256 -in certs/island.crt` prints, with
the colons removed and lowercased. `deploy/island-fingerprint.sh` prints it
again any time, in both forms, and checks that the running Caddy presents the
same certificate as the file.

By hand, without the installer, it is the same three steps. Issue the
certificate:

```bash
mkdir -p certs
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/island.key
openssl req -new -x509 -key certs/island.key -sha256 -days 3650 \
    -subj "/CN=203.0.113.5" -addext "subjectAltName=IP:203.0.113.5" -out certs/island.crt
chmod 600 certs/island.key certs/island.crt
```

(`DNS:island.example` in the SAN, and as the CN, for a name; both entries,
comma-separated, for a name and its IP.) Then the three `.env` lines above
and `docker compose up -d`.

⚠ Keep OpenSSL 3's `req -x509` defaults, which set `basicConstraints CA:TRUE`
and a subject key identifier, and keep the address in the SAN. The phones and
the desktop pin the fingerprint and would accept any certificate; the CLI
runs on Node, which can only be handed a trust anchor, and a certificate
without those extensions or without the SAN is refused there and nowhere
else.

The masquerade Caddyfiles are CA-mode files. A closed island without an
authority needs the two merged by hand (the global block and the `tls` line
from the fingerprint file into the masquerade one); it is not done here.

### What users see

An island without a certificate authority opens in RCQ for **Android, iOS,
the desktop app and the CLI**. It does not open in a browser: a browser
cannot be told to trust a private certificate, there is nothing an operator
can do about that, and the address form of the web client says so when an
address carries a fingerprint or is a bare IP.

1. **The careful way.** The person enters the address exactly as you handed
   it out, `203.0.113.5#ab12cd34…` (a pasted `https://203.0.113.5/#ab12…` and
   openssl's `AB:12:CD:…` form both work). The app stores the fingerprint
   before it connects, and the island has to match it: a mismatch is refused,
   with a banner saying the island presented a different fingerprint than the
   one entered. No trust on first use at all.
2. **The quick way.** The person enters only `203.0.113.5`. The app connects,
   pins whatever the island presented, and shows one dismissible notice:
   "First connection to 203.0.113.5. Its fingerprint is … Compare it with what
   the operator published." Not a dialog, nothing is blocked; it is shown once.
3. **Every later connection** has to present the same certificate. A
   different one is not connected to at all: a red banner at the top of the
   main screen names the island, the fingerprint on file and the new one,
   with "Trust the new fingerprint" and "Not now". Until the person decides,
   the app is offline for that island.
4. **Settings**, on the island's row: "Trusted by fingerprint" with the
   fingerprint in display form (sixteen groups of four, four to a line, the
   same as the installer prints) and a copy action for the whole
   `address#fingerprint`, so users can pass the island on to each other in
   the careful form.

People on other islands reach yours by `uin@address`, and their apps pin it
on first contact the same way; the careful form for them is the same line.

### Handing out the address

Publish `address#fingerprint` somewhere the person already trusts and the
network cannot rewrite: said in person, sent in an existing RCQ or Signal
conversation, printed on paper. A web page on the island itself is the one
place it proves nothing, and so is `/server/info`: a fingerprint read over
the very connection it is meant to verify is no check at all, which is why
the island does not advertise it.

The trust model, in one paragraph:
[SECURITY.md](../SECURITY.md#islands-trusted-by-fingerprint).

### Rotating the certificate

Do not, unless you have to. The certificate lasts ten years and the key is
the island's identity; a new one means every user sees the red banner and has
to compare and accept a new fingerprint. When you must (the key leaked, or
`certs/` was lost: a lost key IS a rotation):

1. Announce the new fingerprint first, out of band, and in the island's news
   while the old certificate is still up: nobody can read the news once
   their app refuses the connection.
2. Issue the new pair with the recipe above. Move the old files aside rather
   than overwriting them, until the new ones are confirmed live.
3. `docker compose restart caddy`. ⚠ Caddy reads the files at start; until
   the restart it keeps serving the old certificate, and the file on disk
   says nothing about that. `deploy/island-fingerprint.sh` compares the file
   with the wire for exactly this reason.
4. `deploy/island-fingerprint.sh` for the new line to hand out.

Back up `certs/` together with `.env`
([backup-and-recovery.md](backup-and-recovery.md)): the island's identity and
its secrets, and neither is in git.

### Moving to a certificate authority later

Once a name points at the host, the move is a `.env` edit and a restart:

```ini
RCQ_DOMAIN=island.example
RCQ_TLS_MODE=ca
RCQ_CADDYFILE=./deploy/Caddyfile.compose
```

`docker compose up -d` recreates Caddy on the new file, and Let's Encrypt
does the rest (answer 1 or 2 included, if you set them up).

What users see depends on how they added the island, and for the careful
ones it is not nothing:

* Added by **name, the quick way** (they typed `island.example` and the app
  pinned what it saw), or trusted from a banner: nothing. The next
  connection validates through the authority, the record becomes "trusted
  through a certificate authority", and there is no notice, because nothing
  a person could evaluate has happened.
* Added by **name, the careful way** (`island.example#ab12…`, the form this
  page tells you to hand out): the red banner, once. A typed fingerprint
  wins over an authority. The person gave the app the island's identity out
  of band, and nothing that arrives over the network replaces it on its own,
  an authority's signature included; otherwise anyone able to obtain a
  certificate the platform trusts for your address could have replaced the
  typed pin silently, and the careful way would not have been careful. So
  the banner says the island presented a different fingerprint than the one
  they entered, the app is offline for the island until they press "Trust
  the new fingerprint", and from then on the record is the authority's.
  Announce the move the way a rotation is announced: out of band, and in the
  island's news while the old certificate is still up, with the day, so the
  banner is expected rather than read as an interception. Nobody reads the
  news once their app refuses the connection.
* Added by **IP**: the address itself changes. An app that dials
  `203.0.113.5` after the switch meets either no certificate or one issued
  for the name; either way the island is refused at the old address until
  they add it again as `island.example`. ⚠ So decide at install time: if
  there is any chance of a domain later, give the installer the name now
  (`RCQ_DOMAIN=island.example RCQ_TLS=fingerprint`) even though nothing signs
  it yet. Users type the name, the certificate carries the name and the IP,
  and the move later costs one banner for those who typed the fingerprint
  and nothing for the rest.

The reverse, from an authority back to a private certificate, is a **change**
on every device that has ever validated the island through an authority, not
a first use, and shows the red banner: a known island cannot be downgraded
silently, by you or by anyone between you and your users.

### Bare metal

The same certificate with Caddy outside Docker is the `tls` file directive on
a catch-all site; [bare-metal.md](bare-metal.md) step 7a has the block.
