# FTcore 4.2.5

Release date: 2026-11-12. This release promotes the client stability, advanced CAPTCHA and DTLS readiness changes validated as 4.2.4-test.4 (source a239427a201efb6725f2288ecf1c0986cfee6a0e).

The DTLS handshake budget starts after TURN allocation/forwarding readiness. Waiting for authorization or a browser proof no longer consumes handshake slots or handshake time. Primary typed DTLS errors are retained. Default timeouts, CLI flags, mobile API and the server wire protocol stay compatible.

Advanced browser proof capture is opt-in in the standalone core. An Android host needs IPC v2 (or the optional AAR BrowserPowSink API) to present it; receiving a proof or CAPTCHA token does not mean the tunnel is ready. Manual-only options take precedence, rate/service cooldowns are preserved, and manual rejection pauses fresh authorization for explicit resume. The existing server does not require deployment for this client change.

Validation inherited from test.4: 456 root tests, 40 relay integration/unit tests under the integration tag, 135 TURN dependency tests, 12/12 repeated new regression scenarios, Go vet and lint. On Honor/API33, all 11 native dtlsdial/udprelay/new integration tests passed with matching fixture hashes. Release CI must pass for the final release commit before tagging/publishing.

Scope limits: the historical long session had outbound WireGuard TCP timeouts that this DTLS fix does not establish as resolved. Stale-nonce 438 has an existing bounded update/retry path and was not rewritten. No universal CAPTCHA acceptance guarantee or sustained >=12-minute live acceptance is claimed. Generic CAPTCHA-proxy cleanup cancellation logging remains a separate diagnostic observation.

Older test handoffs describe their original freeze and acceptance state; this release document and the 4.2.5 release checks supersede their publication hold for this user-authorized release. Test artifacts and tags are preserved.
