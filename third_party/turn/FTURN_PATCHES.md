# Local Pion TURN v5.0.12 patches

This directory is copied from the verified Go module github.com/pion/turn/v5 v5.0.12.
The original MIT license and source headers are retained.

- Export BindingRefreshInterval and BindingCheckInterval so the application can
  renew ChannelBind permissions before their five-minute expiry, including idle
  channels. Defaults are two minutes and ten seconds.
- Return the TURN error for non-438 Refresh error responses (upstream returned
  the nil result of parsing ERROR-CODE). Reject missing/wrong response types,
  missing LIFETIME and zero LIFETIME during renewal.
- Recompute the allocation refresh interval after a successful lifetime update;
  retry failed renewals after at most five seconds.
- Log Refresh and ChannelBind transaction IDs, elapsed times, response types,
  error codes/reasons, lifetimes and refresh/expiry timing. Credentials and nonce
  values are not logged.
- Preserve upstream saved-channel handling for ambiguous 400 replies. The
  application's watcher recycles the allocation after repeated binding or
  allocation refresh failures, with independent success/failure counters.

- Add OnListenerError to report terminal receive-loop failures after canceling
  pending transactions, so the application can reconnect without waiting for
  another write or the smux keepalive timeout.

Regression tests: go test ./... from this directory.
