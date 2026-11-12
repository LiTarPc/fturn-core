# RAW Android verification IPC v1

Opt in with FREETURN_RAW_CAPTCHA_TOKEN (64 hex chars / 256 bits) and
FREETURN_RAW_CAPTCHA_GENERATION (8..128 ASCII alphanumeric, underscore, hyphen).
FREETURN_RAW_BROWSER_CAPTCHA=1 selects the browser-first solver unless the
profile explicitly requests manual-only. No IPC environment means legacy CLI.

Go listens only at 127.0.0.1:ephemeral. Every request requires:
Authorization: Bearer <token>
X-Fturn-Generation: <generation>
Host must match 127.0.0.1:<port>. Origin and URL queries are rejected.

stdout lines begin exactly FTURN_EVENT followed by space and one JSON object:
{v:1,type:"captcha",generation,request_id,mode:"browser"|"manual",
 phase:"pending"|"resolved"|"expired"|"cancelled"|"unavailable",
 expires_at_ms,ipc_port}
No private URL, token or solution appears in the event.

GET /v1/captcha/<request_id> returns JSON:
{generation,request_id,mode,expires_at_ms,url}
URL is an http://localhost:8765 or http://127.0.0.1:8765 verification-proxy URL.
The host validates generation, ID, TTL, scheme, port and origin before loading.

POST /v1/captcha/<request_id>/host, JSON:
{generation,status:"available"|"unavailable"|"manual_requested",reason}
reason is empty or host_unavailable|renderer_gone|load_failed|challenge_expired|
user_requested. Body is capped at 2048 bytes; unknown keys/trailing JSON rejected.
Unavailable or manual_requested promotes the SAME challenge/URL/ID to manual.
After 45s without a result, browser mode also becomes manual. The original
3-minute overall deadline is not extended. Same-ID manual pending must expose
the existing WebView rather than silently reload the page.
Results go to the existing local verification proxy, not through IPC.

A failure/timeout or a rejected browser result pauses new authorization. Event:
{v:1,type:"auth",phase:"waiting_user"|"resuming"|"authorized",generation,ipc_port}
POST /v1/auth/resume with the same auth headers resumes only on explicit user
request (no body required), idempotently. Existing cached credential groups and
active allocations keep working. Intentional user wait must not trigger an
Android watchdog restart even when no workers are ready.

HTTP: 200 successful GET; 204 successful host/resume; 400 malformed fields;
401 missing/wrong bearer; 403 Origin/Host forbidden; 409 stale generation;
410 nonexistent/finished/expired challenge. A process restart invalidates all
previous IDs, secrets and generation values. Never put these headers/private
responses in general logs or diagnostic metadata.

After an explicit resume, fresh credential success emits auth/authorized even
when no new captcha is required. This clears the RESUMING presentation, not the
ready-worker count. Cached credential hits never emit it. An existing pending
challenge or a new WAITING_USER pause cannot be cleared by this notification.


# Verification IPC v2 — advanced browser PoW (RAW proposal, 2026-11-07)

The v1 contract above remains byte-compatible by default. Opt in to v2 with
FREETURN_RAW_CAPTCHA_PROTOCOL=2 plus the same per-process TOKEN/GENERATION.
FREETURN_RAW_ADVANCED_CAPTCHA=1 (or -advanced-captcha / vk.advancedCaptcha=true)
selects advanced authorization; default is false. Advanced + authenticated IPC
requires protocol=2; fail startup for unsupported combinations instead of silently
loading a capture page into a v1 manual host. Manual-only overrides advanced and
auto settings. -auto-captcha=false / vk.autoCaptcha=false selects manual-only.
FREETURN_RAW_BROWSER_CAPTCHA=1 alone retains the old v1/v2 token-wait behavior;
when advanced is explicitly enabled, it no longer bypasses the automatic solver.
No IPC environment preserves ordinary CLI/manual presentation.

In v2 ALL events have v=2, and captcha events and GET descriptors additionally
have purpose="pow_capture" or "solve". Mode remains browser|manual.
Authenticated HTTP routes, headers, TTL, generation/request_id checks and fixed
verification origin remain /v1/... for both envelope versions. The HTTP route
version names the transport resource; v names the negotiated event semantics.

purpose=pow_capture:
- browser/pending: load the private page in the service-owned background WebView.
- captured: terminal for THIS capture page; destroy/close that page only. This
  means the core received an envelope, NOT that it validated it, solved CAPTCHA,
  submitted a success token, obtained credentials or has any ready channels.
- unavailable|expired|cancelled: terminal; close the capture host. Never expose
  the same capture page as a manual solver and never convert it after 45s.
- capture deadline is 12 seconds, bounded by the caller; no automatic TTL extension.
- POST host unavailable/manual_requested ends capture and cancels its local
  server; automatic policy decides legacy/manual fallback. GET/late host replies
  for a terminal request receive 410. No PoW travels through metadata IPC.

purpose=solve retains existing browser/manual token behavior and 45s browser to
manual transition if browser mode was selected. Advanced automatic fallback uses
manual/solve as a SEPARATE request ID/page, with a fresh challenge when prior
verification may have consumed it. Manual-only never creates pow_capture.

captcha/solve/resolved only means a page returned a success token; the core still
must submit it and finish its credential chain. In v2 auth/authorized is emitted
only after fresh credential success (including initial authorization), never on
capture/token receipt or cached hits. It cannot clear a newer waiting_user or
pending challenge. The ready-worker count remains a separate transport state.

Android must parse v2 BEFORE ordinary logging and reject unknown purpose/phase
pairs. Do not mark the VPN connected from captured/resolved alone. Continue the
connecting/authorizing state until actual credentials/ready counters arrive.
Keep one active host, apply STOP/TTL/generation cleanup and stale-ID rejection.
Treat unsupported v2 as a visible integration error, never auto-resume or restart
VPN. Feature setting is applied on the next connection, not a live mutation.

A capture error can fall back to one legacy automatic attempt if no refusal,
rate limit or cancellation occurred. Invalid/mismatched browser proof is never
submitted. BOT disables automatic checks for the process; limited responses keep
Retry-After/cooldown. Any automatic solver failure that may have consumed the
challenge requests at most one fresh manual challenge, preserving identity and
client_id; manual failure/repeated challenge pauses for explicit user action.
Cookies and private results must stay in memory; no raw payload/telemetry or
secret-bearing URL in events, errors, diagnostics or test reports.

Integration status: contract proposal owned by RAW, to be shared with TURN and
Android before either updates pinned clients. Native/fixture tests cannot prove
acceptance by VK; real Android WebView E2E is a separate acceptance step.
