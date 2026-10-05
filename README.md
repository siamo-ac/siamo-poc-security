# siamo-poc-security

POC 9 of the Siamo backend-architecture series: **security fundamentals in
one small Go service** — JWT auth, OAuth2 (client-credentials grant), HTTPS
with a self-signed cert, and an encrypted-at-rest secret store. Built to
*show* the concepts in a live demo, not to protect anything real.

## The concept (plain language)

Four ideas carry this demo:

1. **Tokens, not trust.** To call a protected route you present a signed
   token (JWT). The server checks the signature on *every request* — no
   sessions, no "you're inside the firewall so you're fine". No token,
   no entry.
2. **OAuth2: how machines get tokens.** JWT is the token *format*; OAuth2
   is the *protocol for obtaining one*. This demo has two ways in:
   `POST /login` (a human proving a password) and `POST /oauth2/token`
   with `grant_type=client_credentials` (a service proving its
   `client_id` + `client_secret` — no human in the loop, the standard
   machine-to-machine pattern). Both return a JWT access token, and the
   resource server (`/protected`, `/secrets/...`) validates both the same
   way. That separation — *issuing* tokens vs *accepting* them — is the
   core OAuth2 idea.
3. **Encrypt in transit.** The whole API runs over HTTPS, so tokens and
   secrets can't be sniffed off the wire. The certificate is self-signed
   and generated at startup — fine for a demo, never for production.
4. **Encrypt at rest.** Secrets are encrypted with AES-256-GCM *before*
   they hit disk and decrypted only in memory on read. Steal the disk and
   you get noise, not secrets.

See [docs/zero-trust.md](docs/zero-trust.md) for how "never trust, always
verify" maps onto this code.

## Run the demo

Needs Go (1.21+). All commands from this directory.

**One-command guided demo:**

```bash
./scripts/demo.sh
```

**Manual run:**

```bash
go run ./cmd/server -addr 127.0.0.1:8443
```

Then in another terminal:

```bash
# 1. Public route — no token needed (200)
curl -k https://127.0.0.1:8443/public

# 2. Protected route — NO token (401)
curl -k -i https://127.0.0.1:8443/protected

# 3. Get a token (demo creds: admin / demo1234)
TOKEN=$(curl -sk -X POST https://127.0.0.1:8443/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","password":"demo1234"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

# 4. Protected route — WITH token (200)
curl -k -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/protected

# 5. Store a secret, then read it back
curl -k -X POST https://127.0.0.1:8443/secrets/api-key \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"shhh-very-secret"}'
curl -k -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/secrets/api-key

# 6. OAuth2 instead of login: machine client gets an access token
OAUTH_TOKEN=$(curl -sk -X POST https://127.0.0.1:8443/oauth2/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=svc-reporting' \
  -d 'client_secret=svc-secret-42' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# 7. The OAuth2 access token works on the same protected routes
curl -k -H "Authorization: Bearer $OAUTH_TOKEN" https://127.0.0.1:8443/protected

# 8. Wrong client secret -> 401 {"error":"invalid_client"}
curl -sk -X POST https://127.0.0.1:8443/oauth2/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=svc-reporting' \
  -d 'client_secret=wrong'
```

**Watch the TLS handshake:**

```bash
curl -kv https://127.0.0.1:8443/public 2>&1 | grep -iE 'TLS|SSL connection|subject|issuer'
```

You'll see the TLS 1.2/1.3 negotiation, the cipher suite, and our
self-signed cert (`subject: CN=siamo-poc-security demo`). The `-k` flag
is you telling curl to *skip* verification — that's exactly what real
clients must never do with a self-signed cert.

Env overrides: `JWT_SECRET`, `STORE_KEY` (demo defaults if unset).

## What to observe

- **401 vs 200**: same URL, same server — without the `Authorization:
  Bearer` header you get `401 {"error":"unauthorized"}`; with a valid
  token you get `200`. No IP allow-listing, no exceptions: proof or denial.
- **Token expiry**: tokens live 15 minutes. Wait (or mint one and edit the
  demo TTL) and the same token starts getting 401 "token expired".
- **Encrypted bytes on disk**: after storing a secret, open
  `data/secrets.json` (or `/tmp/pocsec-data/secrets.json` after the demo
  script). You'll see base64 `nonce` + `ct` fields — the plaintext never
  appears. `grep shhh data/secrets.json` finds nothing.
- **HTTPS everywhere**: every route, including `/login` and `/oauth2/token`,
  is TLS-only. There is no HTTP fallback.
- **OAuth2 flow, end to end**: the token endpoint speaks the real
  `client_credentials` grant shape (form-encoded `grant_type`, `client_id`,
  `client_secret` → `access_token` + `token_type: Bearer` + `expires_in`).
  Wrong secret → `401 {"error":"invalid_client"}`. The issued access token
  carries `sub: "client:svc-reporting"` — open it at jwt.io and compare
  with a `/login` token to see the *format* is identical; only the *issuer
  path* differs. That is the OAuth2 lesson: one token format, two ways to
  earn it, one way to check it.

## Honest limits (POC — not production hardening)

- **Self-signed certificate.** Browsers and clients warn on these for a
  reason. Production uses a real CA (e.g. Let's Encrypt) — and no `-k`.
- **HS256 with a shared demo secret.** Anyone holding the secret can mint
  tokens. Production auth uses RS256/JWKS or an identity provider
  (OIDC/SSO), key rotation, and revocation lists.
- **Demo credentials** (`admin`/`demo1234`) are hardcoded. A real system
  has password hashing (bcrypt/argon2), MFA, lockout, the works.
- **Key management**: `STORE_KEY` comes from an env var in this demo.
  Production stores keys in a KMS/vault (HashiCorp Vault, cloud KMS),
  never in the environment.
- No audit logging of access decisions, no rate limiting, no mutual TLS
  between services, no token revocation.
- **OAuth2 is a mock token endpoint only**: `client_credentials` grant,
  hardcoded demo client, no `authorization_code` / `refresh_token` flows, no
  scopes, no token introspection or revocation endpoint. A real deployment
  delegates to an identity provider (Keycloak, Auth0, Entra ID).
- Stdlib only — deliberately no JWT or crypto frameworks, so the demo
  shows the mechanics, not a library.
