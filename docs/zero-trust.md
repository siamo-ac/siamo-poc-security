# Zero Trust, as applied to this POC

**Zero trust in one sentence:** never trust, always verify — every single
request must prove itself, even if the last one from the same place did.

Old-school security works like a castle: a thick wall (the firewall), and
once you're inside the wall you're trusted. The problem is that attackers
*do* get inside the wall — phishing, stolen laptops, a leaked password —
and then nothing stops them from wandering room to room.

Zero trust removes the wall as a concept and puts a locked door on every
room instead. How this POC demonstrates it:

1. **No implicit trust.** There is no "internal network" exception, no
   trusted IP range, no "localhost is fine". A request from 127.0.0.1 with
   no token gets the exact same 401 as one from the open internet.
   (Run `curl -k https://127.0.0.1:8443/protected` with no token — denied.)

2. **Verify every request.** The auth middleware checks the JWT signature
   and expiry on *each* request. Tokens expire after 15 minutes, so a
   stolen token has a short shelf life. There is no session to hijack.

3. **Least privilege by construction.** The `/public` route and `/login`
   are open because they must be (you need a way to get a token); every
   other route requires proof. New routes are protected *by default* —
   you have to deliberately expose something, not deliberately secure it.

4. **Assume breach.** The secret store encrypts values with AES-256-GCM
   *before* writing to disk. If someone steals the server's hard drive,
   they get ciphertext, not secrets. The encryption key is never on disk
   with the data (it's an env var) — separation of key and ciphertext is
   the whole game.

5. **Encrypt in transit too.** TLS (HTTPS) means tokens and secrets can't
   be sniffed off the wire. This POC generates a self-signed certificate
   at startup — fine for a demo where we control both ends, never for
   production (see honest limits in the README).

What this POC does *not* yet do (a real zero-trust deployment also would):
identity federation (SSO/OIDC), per-request device attestation, mutual TLS
between services, audit logging of access decisions, key rotation, and
secret management via a vault rather than env vars. This is the *shape* of
zero trust, not the full build-out.
