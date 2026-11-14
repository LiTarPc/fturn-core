# FTcore 4.2.6

Release date: 2026-11-14.

A manual CAPTCHA page could remain black with only the Ftcore banner: Webpack derives its CDN public path from document.currentScript.src, but the old /generic_proxy?proxy_url=... URL discarded the upstream directory. Its JavaScript chunks were requested from localhost/chunks and reached the page origin instead of st.vk.ru, producing 404 HTML responses and MIME errors.

External assets now use /local-captcha-resource/<base64url-origin>/<original-path>?query. The browser-visible directory is preserved for script chunks, CSS-relative fonts and query parameters. Legacy /generic_proxy links remain supported through the same handler. Request methods, bodies, custom headers, escaped paths, response status and MIME are preserved. Resource transport failures use the existing sanitized error handler; incomplete verification responses fail instead of being treated as successful bodies.

The existing host allowlist is unchanged. Invalid schemes, userinfo and invalid encoded origins are rejected. The separate blocked ad.mail.ru sync-loader is not allowed by this fix. Capture-only mode checks the decoded upstream path on both routes and continues to block check, componentDone, leaveCaptcha and endSession; it cannot accept manual solver tokens.

Offline regressions reproduce the old Webpack path failure and check the two reported chunks, CSS/fonts, HTTPS protocol-relative resources, fetch(Request) POST preservation, HTTP/MIME errors, invalid hosts/origins, capture-only restrictions, manual token delivery and sanitized errors. The existing browser proof observer contract is retained, and both JavaScript suites run in PR CI and release verification. Final Go, security, cross-platform and release checks are recorded by the GitHub Actions runs associated with this release.

Go 1.26.11, Brotli 1.2.7, compress 1.20.2 and pinned gomobile/gobind from 4.2.5 are retained. CLI, mobile API and server wire protocol remain compatible. Existing servers do not need an update for this client fix. Android applications need to integrate the new AAR/native core separately.

Limit: these checks validate resource routing and local behavior. A real VK manual CAPTCHA completion and subsequent tunnel readiness have not been verified; the release does not claim universal CAPTCHA acceptance.
