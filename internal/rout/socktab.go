package rout

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
)

// sockEntry is one bound socket as the kernel reports it in /proc/net. Reading it needs no
// sockets and no privileges, and shows what is ACTUALLY bound (not what was requested).
type sockEntry struct {
	Network string // tcp4, tcp6, udp4, udp6
	IP      netip.Addr
	Port    int
	// Dual is set on an IPv6 wildcard socket: /proc cannot tell whether IPV6_V6ONLY is on, so
	// such a socket may also accept IPv4 connections.
	Dual bool
}

func (s sockEntry) Addr() string { return netip.AddrPortFrom(s.IP, uint16(s.Port)).String() }

// parseProcNet extracts listening sockets (TCP state 0A, unconnected UDP state 07).
func parseProcNet(network string, data []byte) []sockEntry {
	var out []sockEntry
	lines := strings.Split(string(data), "\n")
	for i := 1; i < len(lines); i++ {
		f := strings.Fields(lines[i])
		if len(f) < 4 {
			continue
		}
		state := f[3]
		if (strings.HasPrefix(network, "tcp") && state != "0A") || (strings.HasPrefix(network, "udp") && state != "07") {
			continue
		}
		ipHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		raw, e := hex.DecodeString(ipHex)
		if e != nil {
			continue
		}
		pb, e := hex.DecodeString(portHex)
		if e != nil || len(pb) != 2 {
			continue
		}
		var ip netip.Addr
		switch len(raw) {
		case 4:
			ip = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		case 16:
			var b [16]byte
			for g := 0; g < 4; g++ { // each 32-bit group is stored in host (little-endian) order
				binary.LittleEndian.PutUint32(b[g*4:], binary.BigEndian.Uint32(raw[g*4:]))
			}
			ip = netip.AddrFrom16(b)
		default:
			continue
		}
		out = append(out, sockEntry{Network: network, IP: ip, Port: int(binary.BigEndian.Uint16(pb)), Dual: network[3] == '6' && ip.IsUnspecified()})
	}
	return out
}

// readSockets lists the listening sockets of this host. A family the kernel lacks (no
// /proc/net/tcp6) simply has none.
var readSockets = func() ([]sockEntry, error) {
	var out []sockEntry
	var firstErr error
	any := false
	for _, n := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		file := "/proc/net/" + n[:3]
		if n[3] == '6' {
			file += "6"
		}
		b, e := os.ReadFile(file)
		if e != nil {
			if n[3] == '4' && firstErr == nil {
				firstErr = e
			}
			continue
		}
		any = true
		out = append(out, parseProcNet(n, b)...)
	}
	if !any {
		return nil, firstErr
	}
	return out, nil
}
