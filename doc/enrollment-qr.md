# Enrollment QR: what the phone app scans

Status: **implemented** 2026-11-14. This document is the contract between
`authz-admin enroll-new` and the mobile app's QR scanner. It is written so the
app can be built against it without reading this repository's Go code.

## 1. The payload

The square encodes one absolute URL and nothing else:

```text
https://<origin>/__aivan/enroll?code=<code>
```

Example:

```text
https://aivan-hud.home.arpa/__aivan/enroll?code=Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M
```

| Part | Value |
|---|---|
| scheme | always `https`. A plaintext origin cannot set the `__Host-` session cookie, so the app must refuse `http` |
| host | the origin the operator minted for, taken from `AIVAN_HOSTS` |
| path | always `/__aivan/enroll` |
| query `code` | the enrollment code, URL-escaped, exactly as printed on the line above the square |

The code is 26 Crockford base32 characters with a dash every four. The display
form is what the square carries. Both the page and the claim normalise it, so
case, dashes and the `I`/`L`/`O` confusions do not matter; an app may send the
code as it read it.

**The QR is a URL, not a JSON envelope.** An app that expects a custom scheme,
a `aivan://` deep link, or a JSON body in the square will not match this
payload. If you want one, say so before the next change, because the app and
this command have to move together.

## 2. What the app does with it

Two shapes are supported. Either one ends in the same claim.

**Open the URL in a browser.** The gate serves the page at that path, and the
page reads `?code=`, fills the field, and scrubs the code out of the address
bar. This needs no app code at all beyond opening the URL. It enrolls the
*browser*, not the phone, so it is the wrong shape for a phone that wants its
own device row.

**Claim it from the app.** This is the one that gives the phone a `phone` device
row. The URL is parsed, and the app posts the five-field claim itself:

```text
POST /__aivan/enroll
Content-Type: application/json

{ "code":       "<the code from ?code=>",
  "kind":       "phone",
  "alg":        "ed25519",
  "public_key": "<base64url raw Ed25519 public key>",
  "signature":  "<base64url Ed25519 signature over the canonical string>" }
```

The canonical string is the exact bytes the app signs:

```text
aivan-enroll-v1
<normalised code>
<alg>
<public_key>
```

`<alg>` and `<public_key>` are the strings the body carries, unchanged. The
separator is a single newline with no trailing newline. The normalised code is
upper-case, with every character that is not `[A-Z0-9]` dropped, and `I`/`L`
read as `1` and `O` as `0`.

A `201` returns `device_id`, `user_id` and `username` and sets
`__Host-aivan_session`. A `403` is the single constant denial: the code is
wrong, spent, expired, or minted for another origin, and the response will not
say which. A `400` means the request was malformed, which is a bug in the app
rather than a bad code.

The device's kind comes from the minted record, not from the body. An operator
who minted `--kind phone` produces a phone device even if the body says
`browser`.

## 3. What the app must send afterwards

- The session is the `__Host-aivan_session` cookie. It requires `https`, and it
  is `Secure`, `HttpOnly`, and `Path=/`.
- Every non-GET under that cookie carries `X-Aivan-Csrf`. A native client has no
  `Sec-Fetch-Site`, so the header is the only path.
- Sign-out is `DELETE /__aivan/session` with that header.

`aivan-authz/doc/auth.md` in the companion checkout has the same rules from the
gate's side, and `aivan-authz/test/drill/phone` is a runnable client that
performs the whole loop, including a gated request and sign-out.

## 4. What the app must not assume

- **The code is single-use and expires in 15 minutes.** A scan is a claim, so a
  scan that is retried after a failure may find the code spent.
- **The code is a secret.** It is in a URL because that is what a camera can
  carry, and the page removes it from the address bar on load. An app should do
  the same: do not keep the scanned URL in a log, a screenshot, or a history
  entry.
- **The square is a display, not a second credential.** Only the digest of the
  code is stored, so neither the command nor the app can recover a lost code;
  the operator mints another.

## 5. Verifying a change to the payload

`internal/console/qr_test.go` pins the URL and the drawing, and
`cmd/authz-admin/enroll_integration_test.go` runs the real binary, mints a real
code, and compares the drawn square module-for-module against the encoder's
bitmap for that exact URL. A change to the payload or to the drawing fails both.
