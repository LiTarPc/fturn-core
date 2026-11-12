// Package limits defines payload limits compatible with existing FTcore servers.
package limits

const (
	// Datagram is the maximum DTLS record carried by the existing UDP relay.
	Datagram = 1600
	// UDPApplication also reserves worst-profile obf, DTLS CID and IPv6 TURN
	// SendIndication overhead inside the existing 1600-byte TURN receive buffer.
	UDPApplication = 1440
	// TunnelMTU leaves the WireGuard transport header and 16-byte padding room.
	TunnelMTU = UDPApplication - 32
)
