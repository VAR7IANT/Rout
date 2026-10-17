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

func (m nftMeter) prefix() string {
	h := sha256.Sum256([]byte(m.home))
	return fmt.Sprintf("rout_%x_", h[:4])
}
func (m nftMeter) table(p Profile) string { return m.prefix() + p.ID }
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
		out := strings.TrimSpace(string(b))
		if strings.Contains(out, "Operation not permitted") || strings.Contains(out, "Permission denied") {
			return nil, fmt.Errorf("nftables 权限不足：需要 root 和 CAP_NET_ADMIN；OpenVZ/部分 LXC 容器不授予该权限，流量统计与限额不可用：%s", out)
		}
		if strings.Contains(out, "Protocol not supported") || strings.Contains(out, "not supported") {
			return nil, fmt.Errorf("内核不支持 nf_tables，流量统计与限额不可用（容器内核可能缺少模块）：%s", out)
		}
		return nil, fmt.Errorf("nftables 操作失败，请检查 nft、CAP_NET_ADMIN 和内核支持：%s", out)
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
func decodeNFT(b []byte) ([]map[string]any, error) {
	var root struct {
		NFT []map[string]any `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(&root); e != nil {
		return nil, e
	}
	return root.NFT, nil
}
func parseNFT(b []byte) (MeterSnapshot, error) {
	entries, e := decodeNFT(b)
	if e != nil {
		return MeterSnapshot{}, e
	}
	return parseEntries(entries)
}

// The table an nft JSON object belongs to ("table" objects carry their own name).
func entryTable(entry map[string]any) string {
	for kind, v := range entry {
		o, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if kind == "table" {
			name, _ := o["name"].(string)
			return name
		}
		name, _ := o["table"].(string)
		return name
	}
	return ""
}
func parseEntries(entries []map[string]any) (MeterSnapshot, error) {
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
	for _, entry := range entries {
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

// ReadAll lists every inet table once. Each Rout table is parsed exactly like a single
// "list table"; any table whose batched result is not healthy is re-read on its own,
// so batching can only save work, never change a verdict.
func (m nftMeter) ReadAll(ps []Profile) (map[string]meterRead, []string) {
	out := map[string]meterRead{}
	single := func(p Profile) { s, e := m.Read(p); out[p.ID] = meterRead{s, e} }
	b, e := nftRun("", "-j", "list", "ruleset", "inet")
	var entries []map[string]any
	if e == nil {
		entries, e = decodeNFT(b)
	}
	if e != nil {
		for _, p := range ps {
			single(p)
		}
		return out, nil
	}
	groups := map[string][]map[string]any{}
	for _, entry := range entries {
		if name := entryTable(entry); strings.HasPrefix(name, m.prefix()) {
			groups[name] = append(groups[name], entry)
		}
	}
	known := map[string]bool{}
	for _, p := range ps {
		name := m.table(p)
		known[name] = true
		group, ok := groups[name]
		if !ok {
			out[p.ID] = meterRead{err: errMeterMissing}
			continue
		}
		snap, e := parseEntries(group)
		if e != nil {
			single(p)
			continue
		}
		out[p.ID] = meterRead{snap: snap}
	}
	var orphans []string
	for name, group := range groups {
		// Only tables carrying Rout's own comment are ever considered for removal.
		if _, e := parseEntries(group); e == nil && !known[name] && idPattern.MatchString(strings.TrimPrefix(name, m.prefix())) {
			orphans = append(orphans, name)
		}
	}
	return out, orphans
}
func (m nftMeter) RenewAll(ps []Profile) error {
	var s strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&s, "flush set inet %s alive\nadd element inet %s alive { %d timeout 15s }\n", m.table(p), m.table(p), p.Port)
	}
	return nftApply(s.String())
}
func (m nftMeter) DeleteTables(names []string) error {
	var s strings.Builder
	for _, name := range names {
		s.WriteString("delete table inet " + name + "\n")
	}
	return nftApply(s.String())
}
func (m nftMeter) Replace(p Profile, r TrafficRecord) (string, error) {
	name := m.table(p)
	// "add" then "delete" removes any previous generation in the same atomic transaction.
	s := "add table inet " + name + "\ndelete table inet " + name + "\n" + fmt.Sprintf("table inet %s {\ncomment \"Rout traffic v1\";\ncounter up { packets 0 bytes %d; }\ncounter down { packets 0 bytes %d; }\n", name, r.RawUp, r.RawDown)
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
