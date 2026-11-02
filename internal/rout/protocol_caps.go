package rout

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Transport capability model.
//
// A plain TCP port mapping carries TCP and nothing else: it can never carry the UDP
// datagrams of QUIC-based protocols, and Rout does not pretend otherwise by writing UDP
// into a TCP socket. This file states which transports each protocol needs and compares
// that with what a destination is known to accept.
//
// UDP-over-TCP encapsulation was evaluated and deliberately NOT implemented: it needs a
// compatible decapsulating peer on the remote side (which an arbitrary NAT or third-party
// server does not have), adds head-of-line blocking that defeats QUIC congestion control,
// and cannot be made transparent to Hysteria2/TUIC. A relay therefore either forwards UDP
// to a UDP-capable destination or refuses; it never silently degrades.

// schemeInfo describes a share-link scheme.
type schemeInfo struct {
	Label    string   // human name
	Networks []string // transports the protocol needs ("tcp"), or may use ("tcp","udp")
	QUIC     bool     // the protocol runs over QUIC (UDP only)
}

var schemeTable = map[string]schemeInfo{
	"vless":     {Label: "VLESS", Networks: []string{"tcp"}},
	"anytls":    {Label: "AnyTLS", Networks: []string{"tcp"}},
	"trojan":    {Label: "Trojan", Networks: []string{"tcp"}},
	"ss":        {Label: "Shadowsocks", Networks: []string{"tcp", "udp"}},
	"hy2":       {Label: "Hysteria2", Networks: []string{"udp"}, QUIC: true},
	"hysteria2": {Label: "Hysteria2", Networks: []string{"udp"}, QUIC: true},
	"tuic":      {Label: "TUIC", Networks: []string{"udp"}, QUIC: true},
}

func linkScheme(raw string) string {
	if u, e := url.Parse(strings.TrimSpace(raw)); e == nil {
		return strings.ToLower(u.Scheme)
	}
	return ""
}

// identifyLink names what a share link is and which transport its relay needs, for the
// "recognized" line shown while creating a relay. ok is false for a bare host:port.
func identifyLink(raw string) (label, transport string, ok bool) {
	scheme := linkScheme(raw)
	info, found := schemeTable[scheme]
	if !found {
		return "", "", false
	}
	label = info.Label
	if u, e := url.Parse(strings.TrimSpace(raw)); e == nil {
		q := u.Query()
		switch {
		case q.Get("security") == "reality" && scheme == "vless":
			label = "VLESS Reality"
		case q.Get("security") == "reality" && scheme == "anytls":
			label = "AnyTLS Reality"
		case scheme == "vless" || scheme == "trojan":
			if t := q.Get("type"); t != "" && t != "tcp" {
				label += " " + strings.ToUpper(t)
			}
		}
	}
	switch {
	case len(info.Networks) == 2:
		transport = "both"
	default:
		transport = info.Networks[0]
	}
	return label, transport, true
}

// quicProtocolName returns "Hysteria2" / "TUIC" for QUIC links ("" otherwise).
func quicProtocolName(raw string) string {
	if info, ok := schemeTable[linkScheme(raw)]; ok && info.QUIC {
		return info.Label
	}
	return ""
}

// networkAllowed reports whether a destination known to accept `known` carries `network`.
// Unknown (empty) allows everything: it is a statement of ignorance, not of support.
func networkAllowed(known, network string) bool {
	switch known {
	case "", "both":
		return true
	}
	return known == network
}

// errTCPOnlyTarget is the message for a UDP protocol aimed at a destination that only
// accepts TCP (for example a NAT that maps TCP ports only).
func errTCPOnlyTarget(protocol string) error {
	if protocol == "" {
		protocol = "Hysteria2 / TUIC"
	}
	return fmt.Errorf("目前目标仅支持 TCP。%s 需要 UDP 传输，无法通过普通 TCP 端口中转直接使用。请选择 UDP 中转，或使用具备 UDP 封装能力的兼容隧道", protocol)
}

// checkTargetNetwork enforces the capability model on a relay. It reports only definite
// contradictions, so an existing relay (which carries no declaration) is never rejected.
func (p Profile) checkTargetNetwork() error {
	switch p.TargetNetwork {
	case "", "tcp", "udp", "both":
	default:
		return errors.New("目标网络类型无效")
	}
	if p.Kind != "relay" {
		return nil
	}
	for _, n := range p.Networks() {
		if !networkAllowed(p.TargetNetwork, n) {
			if n == "udp" {
				return errTCPOnlyTarget(quicProtocolName(p.TargetURI))
			}
			return errors.New("目标仅支持 UDP，不能转发 TCP")
		}
	}
	return nil
}

// mismatchError explains a link whose protocol needs a different transport than the relay.
func mismatchError(raw, relayNetwork string) error {
	info, ok := schemeTable[linkScheme(raw)]
	if ok && len(info.Networks) == 1 {
		switch {
		case info.Networks[0] == "udp" && relayNetwork == "tcp":
			return fmt.Errorf("%s 需要 UDP 传输，TCP 中转无法使用。请选择 UDP 中转，或使用具备 UDP 封装能力的兼容隧道", info.Label)
		case info.Networks[0] == "tcp" && relayNetwork == "udp":
			return fmt.Errorf("%s 使用 TCP，不能通过 UDP 中转转发，请选择 TCP 中转", info.Label)
		}
	}
	return errors.New("转发网络与节点协议不匹配")
}
