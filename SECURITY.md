# Security Policy

RCQ is a privacy- and censorship-resistance-focused messenger. This repo is the
RCQ backend / self-host "island" server (the same code that runs `api.rcq.app`).
We take security reports seriously and welcome good-faith research.

## Reporting a vulnerability

**Please report security issues privately — do NOT open a public GitHub issue
for a vulnerability.**

- **Email:** security@rcq.app
- **In-app:** message the maintainers at RCQ UIN **#911** (end-to-end encrypted).

Please include:
- a description of the issue and its impact,
- the affected component (backend `api.rcq.app` / self-host island, relays + the
  relay broker, the iOS / Android apps),
- the version / commit, and
- steps to reproduce (a proof-of-concept is appreciated).

If you wish to encrypt your report by email and we have not yet published a PGP
key, send a first contact and we will establish an encrypted channel, or use the
in-app E2E path above.

## Our commitment

- We will **acknowledge** your report within **72 hours**.
- We will give you an **assessment and a remediation timeline** within **7 days**.
- We practice **coordinated disclosure**: we ask for up to **90 days** to ship and
  roll out a fix before public disclosure, and we are happy to disclose sooner
  once a fix is deployed and users have had a chance to update.
- With your permission, we will **credit** you in the release notes / a security
  acknowledgements list.

## Scope

**In scope**
- The backend API (`api.rcq.app`) and the self-host "island" server (this repo).
- The relay / circumvention transport and the relay broker
  (`app/routers/broker.py`), and the closed-island access gate
  (`/gate/check`, `/gate/redeem`, the masquerade Caddyfiles).
- The cryptographic protocols (sealed sender, the v=1/v=2 message envelopes,
  sender keys, the federation home-island records, the relay-config + broker
  signatures).
- The iOS app (`github.com/rcq-messenger/rcq-ios`) and the Android app
  (`github.com/rcq-messenger/rcq-android`).

**Out of scope**
- Volumetric denial-of-service / traffic flooding.
- Social engineering of our team or users; physical attacks.
- Vulnerabilities in third-party dependencies that are already public and have an
  upstream fix (please still tell us so we can bump them).
- Reports from automated scanners with no demonstrated impact.

## Safe harbor

We will not pursue or support legal action against researchers who, in good
faith:
- make a reasonable effort to avoid privacy violations, data destruction, and
  service degradation,
- only interact with accounts/servers they own or have explicit permission to
  test, and
- give us a reasonable time to remediate before public disclosure.

If in doubt, ask first via the contacts above.

## Islands trusted by fingerprint

An island run without a certificate authority (`RCQ_TLS_MODE=fingerprint`,
[docs/tls-without-a-ca.md](docs/tls-without-a-ca.md)) is identified by the
SHA-256 fingerprint of the certificate it serves. The apps trust it the way SSH
trusts a host key: on the first connection they pin whatever the island presents
and say so once; on every later connection the certificate has to be the same
one, and a different one is refused, not connected to, until the person compares
the new fingerprint with what the operator published and accepts it. The careful
path removes the first-use gap entirely: the operator hands out the address as
`host#fingerprint` over a channel the person already trusts, and the app checks
the island against the typed fingerprint before it trusts anything. What the
mode does not do, stated plainly: the first contact with an unknown island over
a hostile network, without a typed fingerprint, can pin an impostor. What that
costs is bounded, not nothing. Every conversation whose peer keys the device
already held stays what it was: sealed sender and end-to-end encryption do not
depend on TLS, and there the impostor sees ciphertext and metadata, not
messages. A contact made for the first time THROUGH the impostor is not covered:
the island serves the peer's key bundle, so an impostor can serve its own and
read those bodies, exactly as a compromised backend could, and only comparing
safety numbers out of band catches it. An island that has once been validated
through a certificate authority on a device cannot be downgraded to a
private certificate silently; that is a change, with the same red banner. And
`api.rcq.app`, with everything under `rcq.app`, is never accepted on first use.

## Verifying what you run

This backend is open source — you can read every line and run it yourself. It is
the same code deployed at `api.rcq.app`. The Android app offers reproducible
release builds (see that repo's `docs/REPRODUCIBLE-BUILDS.md`); the iOS app is
source-transparent (App Store binaries are re-signed by Apple and not
byte-reproducible). Our threat model and honest security boundaries — what's
protected today and the known metadata gaps we're closing — are documented in
`docs/` and the project transparency materials.
