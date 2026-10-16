package rout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// No shell, no global firewall flushes, no engine API, no packet capture daemon.
type nftMeter struct{ home string }

func (m nftMeter) table(p Profile) string {
	h := sha256.Sum256([]byte(m.home))
	return fmt.Sprintf("rout_%x_%s", h[:4], p.ID)
}
func nftRun(input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "nft", args...)
	c.Env = append(os.Environ(), "LC_ALL=C")
	if input != "" {
		c.Stdin = strings.NewReader(input)
	}
	b, e := c.CombinedOutput()
	if e != nil {
		if strings.Contains(string(b), "No such file or directory") && strings.Contains(string(b), "list table") {
			return nil, errMeterMissing
		}
		if len(b) > 2048 {
			b = b[:2048]
		}
		return nil, fmt.Errorf("nftables 操作失败，请检查 nft、CAP_NET_ADMIN 和内核支持：%s", strings.TrimSpace(string(b)))
	}
	return b, nil
}
func nftApply(s string) error { _, e := nftRun(s, "-f", "-"); return e }
func (m nftMeter) Read(p Profile) (MeterSnapshot, error) {
	b, e := nftRun("", "-j", "list", "table", "inet", m.table(p))
	if e != nil {
		return MeterSnapshot{}, e
	}
	return parseNFT(b)
}
func parseNFT(b []byte) (MeterSnapshot, error) {
	var root struct {
		NFT []map[string]any `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(&root); e != nil {
		return MeterSnapshot{}, e
	}
	var snap MeterSnapshot
	seenUp, seenDown, owned := false, false, false
	number := func(v any) (uint64, error) {
		n, ok := v.(json.Number)
		if !ok {
			return 0, errors.New("流量计数器损坏或回退")
		}
		return parseUint(n.String())
	}
	var canonical []map[string]any
	for _, entry := range root.NFT {
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		if tab, ok := entry["table"].(map[string]any); ok {
			owned = tab["comment"] == "Rout traffic v1"
		}
		if c, ok := entry["counter"].(map[string]any); ok {
			n, e := number(c["bytes"])
			if e != nil {
				return snap, e
			}
			switch c["name"] {
			case "up":
				snap.Up = n
				seenUp = true
			case "down":
				snap.Down = n
				seenDown = true
			}
		}
		if q, ok := entry["quota"].(map[string]any); ok {
			var e error
			snap.Consumed, e = number(q["used"])
			if e != nil {
				return snap, e
			}
		}
		cleanNFT(entry)
		canonical = append(canonical, entry)
	}
	if !seenUp || !seenDown || !owned {
		return snap, errors.New("流量规则缺失或被外部修改")
	}
	x, _ := json.Marshal(canonical)
	snap.Hash = fmt.Sprintf("%x", sha256.Sum256(x))
	return snap, nil
}

// Handles and stateful values are not part of the structural integrity check.
// All chain hooks, matches, verdicts, quota sizes and set types ARE included.
func cleanNFT(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "handle" || k == "index" || k == "packets" || k == "used" || k == "elem" || k == "expires" {
				delete(x, k)
				continue
			}
			if k == "counter" {
				if c, ok := v.(map[string]any); ok {
					delete(c, "bytes")
				}
			}
			cleanNFT(v)
		}
		// Named counters have bytes at their own level.
		if _, ok := x["packets"]; ok {
			delete(x, "bytes")
		}
	case []any:
		for _, v := range x {
			cleanNFT(v)
		}
	}
}
func (m nftMeter) Replace(p Profile, r TrafficRecord) (string, error) {
	name := m.table(p)
	prefix := ""
	if _, e := m.Read(p); e == nil {
		prefix = "delete table inet " + name + "\n"
	} else if !errors.Is(e, errMeterMissing) {
		return "", e
	}
	s := prefix + fmt.Sprintf("table inet %s {\ncomment \"Rout traffic v1\";\ncounter up { packets 0 bytes %d; }\ncounter down { packets 0 bytes %d; }\n", name, r.RawUp, r.RawDown)
	policy := p.trafficPolicy()
	limited := policy.LimitBytes > 0
	if limited {
		used := r.Consumed
		if used > policy.LimitBytes {
			used = policy.LimitBytes
		}
		s += fmt.Sprintf("quota budget { over %d bytes used %d bytes; }\nset alive { type inet_service; flags timeout; timeout 15s; }\n", policy.LimitBytes, used)
	}
	for _, direction := range []string{"up", "down"} {
		s += "chain " + direction + "_gate {\n"
		if limited && r.Blocked != "" {
			s += "drop\n"
		} else if limited {
			field := "dport"
			if direction == "down" {
				field = "sport"
			}
			for _, network := range p.Networks() {
				s += network + " " + field + " @alive goto " + direction + "_allow\n"
			}
			s += "drop\n"
		} else {
			s += "counter name " + direction + " return\n"
		}
		s += "}\n"
		if limited {
			s += "chain " + direction + "_allow { quota name budget drop\ncounter name " + direction + " return\n}\n"
		}
	}
	for _, hook := range []string{"input", "output"} {
		s += "chain " + hook + " { type filter hook " + hook + " priority 300; policy accept;\n"
		direction, field, address := "up", "dport", "daddr"
		if hook == "output" {
			direction, field, address = "down", "sport", "saddr"
		}
		match := ""
		if p.Listen == "0.0.0.0" {
			match = "meta nfproto ipv4 "
		} else if p.Listen != "::" {
			family := "ip"
			if strings.Contains(p.Listen, ":") {
				family = "ip6"
			}
			match = family + " " + address + " " + p.Listen + " "
		}
		for _, network := range p.Networks() {
			s += fmt.Sprintf("%s%s %s %d jump %s_gate\n", match, network, field, p.Port, direction)
		}
		s += "}\n"
	}
	s += "}\n"
	if e := nftApply(s); e != nil {
		return "", e
	}
	snap, e := m.Read(p)
	return snap.Hash, e
}
func (m nftMeter) Freeze(p Profile) error {
	name := m.table(p)
	return nftApply("flush chain inet " + name + " up_gate\nadd rule inet " + name + " up_gate drop\nflush chain inet " + name + " down_gate\nadd rule inet " + name + " down_gate drop\n")
}
func (m nftMeter) Renew(p Profile) error {
	// Flush + add is one atomic transaction, hence no lease gap.
	return nftApply(fmt.Sprintf("flush set inet %s alive\nadd element inet %s alive { %d timeout 15s }\n", m.table(p), m.table(p), p.Port))
}
func (m nftMeter) Delete(p Profile) error { return nftApply("delete table inet " + m.table(p) + "\n") }
