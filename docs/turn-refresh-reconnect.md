# TURN refresh and stream replacement

Both the server and client should be rebuilt from this change. Deploy the server
first: legacy clients remain accepted but have no stream number and cannot
replace an individual old session. New clients send an extra four-byte stream
number in their first DTLS application record. Old servers accept ordinary
UUID-sized IDs but cannot replace stale sessions; IDs longer than 251 bytes with
this extension require the updated server.

The server replaces a connection only after its DTLS handshake, mode validation
and client allowlist authorization. The key is client ID + proxy mode + stable
stream number. It cancels the old handler and expires its transport I/O; cleanup
from the old handler cannot remove the replacement. Other streams remain live.
Existing TCP application connections on a retired session close; applications
must reconnect them. Replacing a session does not migrate TCP byte streams.

## Renewal timing

Pion TURN previously refreshed ChannelBind after five minutes and checked every
30 seconds. Permission expires after five minutes, even though a channel lives
for ten minutes. With periodic CreatePermission refresh disabled for the VK
workaround, the old timing allowed permission to expire before ChannelBind.
ChannelBind now refreshes after two minutes, checked every ten seconds even when
traffic is idle. This leaves about 170 seconds before permission expiry for
network latency, nonce retry and recovery. A retained channel after a 400 reply
does not count as a successful renewal.

The local Pion dependency also fixes Refresh error responses incorrectly being
returned as nil, validates response method/class and LIFETIME, and recalculates
the timer using half the lifetime actually returned by the server. Failed
allocation refreshes retry after at most five seconds. Two consecutive failures
of either allocation renewal or channel renewal signal allocation recycling;
the counters reset independently only on the corresponding successful reply.

## Debugging a live VK relay

Run the client with `-debug`. Successful and failed Refresh/ChannelBind requests
log transaction ID, stream, server/peer, channel, elapsed time, response type,
error code/reason and renewal timing. Passwords and nonce values are not logged.
Expected channel refresh starts around 2:00--2:10 after binding, well before the
5:00 permission deadline. A 438 should be followed by a retry with a fresh nonce.
Repeated 400/437/timeout results should lead to allocation recycling.

On the server, `Session replaced` reports client, stream, mode and old/new relay
addresses. Confirm that stream N is replaced while neighboring streams stay up.
For live validation, keep traffic running for at least 15 minutes and verify
multiple successful ChannelBind renewals and a successful allocation Refresh.
Test a forced relay transport disconnect and verify that traffic resumes through
the replacement without waiting for the old server handler's idle timeout.

The automated tests cover Refresh errors (400/403/437), stale nonce retry, invalid
responses, changed lifetimes and timer intervals, channel renewal during idle,
hello compatibility, and real DTLS reconnection with UDP backend traffic. The
existing TURN/TCP integration test covers relay transport recovery. Live VK
provider behavior still requires the runtime check above.
