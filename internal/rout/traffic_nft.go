package rout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"text/scanner"
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
		if out == "" {
			out = e.Error()
		}
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
	entries, e := decodeNFT(b)
	if e != nil {
		return MeterSnapshot{}, fmt.Errorf("%s: nft JSON: %w", m.table(p), e)
	}
	return m.parseTable(m.table(p), entries)
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
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("nft JSON 包含多余数据")
	}
	return root.NFT, nil
}

// parseNFT accepts attested JSON. Raw kernel output must pass parseTable first
// so a missing JSON comment is verified from the exact target table as text.
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

const trafficTableComment = "Rout traffic v1"

// Text is used ONLY to attest the missing table comment, never to recover counters
// or rules. Scan quoted strings as tokens so comments/braces inside rule comments
// cannot impersonate a table-level comment. Require exactly the requested inet table.
func verifyNFTText(b []byte, name string) error {
	var s scanner.Scanner
	s.Init(bytes.NewReader(b))
	s.Mode = scanner.ScanIdents | scanner.ScanStrings
	s.Error = func(*scanner.Scanner, string) {}
	next := func(want string) bool { return s.Scan() != scanner.EOF && s.TokenText() == want }
	bad := func() error { return fmt.Errorf("%s: 无法验证 nft 文本中的顶层 Rout 表注释", name) }
	if !next("table") || !next("inet") || !next(name) || !next("{") {
		return bad()
	}
	depth, comments := 1, 0
	for depth > 0 {
		tok := s.Scan()
		if tok == scanner.EOF {
			return bad()
		}
		switch s.TokenText() {
		case "{":
			depth++
		case "}":
			depth--
		case "comment":
			if depth == 1 {
				if s.Scan() != scanner.String {
					return bad()
				}
				value, e := strconv.Unquote(s.TokenText())
				if e != nil || value != trafficTableComment {
					return bad()
				}
				comments++
			}
		}
	}
	if comments != 1 || s.Scan() != scanner.EOF || s.ErrorCount != 0 {
		return bad()
	}
	return nil
}

// Normalize ONLY after ownership verification. Keeping the verified comment in the
// canonical JSON preserves hashes written by versions whose JSON includes it.
func (m nftMeter) attestTable(name string, entries []map[string]any) error {
	var table map[string]any
	for _, entry := range entries {
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		if len(entry) != 1 {
			return fmt.Errorf("%s: nft 对象无效", name)
		}
		for kind, value := range entry {
			obj, ok := value.(map[string]any)
			if !ok || obj["family"] != "inet" || entryTable(entry) != name {
				return fmt.Errorf("%s: nft 表范围无效", name)
			}
			if kind == "table" {
				if table != nil {
					return fmt.Errorf("%s: 重复的 nft 表对象", name)
				}
				table = obj
			}
		}
	}
	if table == nil {
		return fmt.Errorf("%s: 缺少 nft 表对象", name)
	}
	if comment, exists := table["comment"]; exists {
		if comment != trafficTableComment {
			return fmt.Errorf("%s: 表归属验证失败：非 Rout 表注释", name)
		}
		return nil
	}
	b, e := nftRun("", "list", "table", "inet", name)
	if e != nil {
		return fmt.Errorf("%s: 读取表归属注释失败: %w", name, e)
	}
	if e = verifyNFTText(b, name); e != nil {
		return e
	}
	table["comment"] = trafficTableComment
	return nil
}
func (m nftMeter) parseTable(name string, entries []map[string]any) (MeterSnapshot, error) {
	if e := m.attestTable(name, entries); e != nil {
		return MeterSnapshot{}, e
	}
	snap, e := parseEntries(entries)
	if e != nil {
		return MeterSnapshot{}, fmt.Errorf("%s: %w", name, e)
	}
	return snap, nil
}
func parseEntries(entries []map[string]any) (MeterSnapshot, error) {
	var snap MeterSnapshot
	counters, chains, rules := map[string]bool{}, map[string]map[string]any{}, map[string]int{}
	var table, quota, alive bool
	var name string
	number := func(v any) (uint64, error) {
		n, ok := v.(json.Number)
		if !ok {
			return 0, errors.New("流量计数器或配额损坏")
		}
		v64, e := parseUint(n.String())
		if e != nil {
			return 0, fmt.Errorf("流量计数器或配额无效: %w", e)
		}
		return v64, nil
	}
	var canonical []map[string]any
	for _, entry := range entries {
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		if len(entry) != 1 {
			return snap, errors.New("nft 对象无效")
		}
		for kind, value := range entry {
			obj, ok := value.(map[string]any)
			if !ok || obj["family"] != "inet" {
				return snap, errors.New("nft 对象 family 无效")
			}
			current := entryTable(entry)
			if name == "" {
				name = current
			}
			if name == "" || name != current {
				return snap, errors.New("nft 表范围无效")
			}
			objName, _ := obj["name"].(string)
			switch kind {
			case "table":
				if table || obj["comment"] != trafficTableComment {
					return snap, errors.New("表归属验证失败：缺少或无效的 Rout 表注释")
				}
				table = true
			case "counter":
				if (objName != "up" && objName != "down") || counters[objName] {
					return snap, errors.New("流量计数器缺失、重复或无效")
				}
				n, e := number(obj["bytes"])
				if e != nil {
					return snap, e
				}
				if _, e = number(obj["packets"]); e != nil {
					return snap, e
				}
				if objName == "up" {
					snap.Up = n
				} else {
					snap.Down = n
				}
				counters[objName] = true
			case "quota":
				if quota || objName != "budget" {
					return snap, errors.New("流量配额重复或无效")
				}
				quota = true
				var e error
				snap.Consumed, e = number(obj["used"])
				if e != nil {
					return snap, e
				}
				if n, e := number(obj["bytes"]); e != nil || n == 0 {
					return snap, errors.New("流量配额大小无效")
				}
			case "set":
				if alive || objName != "alive" {
					return snap, errors.New("流量租约集合重复或无效")
				}
				alive = true
			case "chain":
				if objName == "" || chains[objName] != nil {
					return snap, errors.New("流量链重复或无效")
				}
				chains[objName] = obj
			case "rule":
				chain, _ := obj["chain"].(string)
				expr, ok := obj["expr"].([]any)
				if chain == "" || !ok || len(expr) == 0 {
					return snap, errors.New("流量规则表达式无效")
				}
				rules[chain]++
			default:
				return snap, fmt.Errorf("未知的流量规则对象 %s", kind)
			}
		}
		canonical = append(canonical, entry)
	}
	if !table || !counters["up"] || !counters["down"] {
		return snap, errors.New("流量表或 up/down 计数器缺失")
	}
	required := []string{"up_gate", "down_gate", "input", "output"}
	if quota {
		required = append(required, "up_allow", "down_allow")
	}
	if quota != alive || len(chains) != len(required) {
		return snap, errors.New("流量链或配额租约结构缺失")
	}
	for _, chain := range required {
		c := chains[chain]
		if c == nil || rules[chain] == 0 {
			return snap, fmt.Errorf("流量链 %s 或其规则缺失", chain)
		}
		if chain == "input" || chain == "output" {
			if c["type"] != "filter" || c["hook"] != chain || c["prio"] != json.Number("300") || c["policy"] != "accept" {
				return snap, fmt.Errorf("流量链 %s 的 Hook/优先级/策略无效", chain)
			}
		} else if _, exists := c["hook"]; exists {
			return snap, fmt.Errorf("流量链 %s 存在额外 Hook", chain)
		}
	}
	for chain := range rules {
		if chains[chain] == nil {
			return snap, fmt.Errorf("规则引用未知链 %s", chain)
		}
	}
	// Do not mutate the input: batched and single reads must see identical state.
	x, e := json.Marshal(canonical)
	if e != nil {
		return snap, e
	}
	var stable any
	d := json.NewDecoder(bytes.NewReader(x))
	d.UseNumber()
	if e = d.Decode(&stable); e != nil {
		return snap, e
	}
	cleanNFT(stable)
	x, e = json.Marshal(stable)
	if e != nil {
		return snap, e
	}
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
		snap, e := m.parseTable(name, group)
		if e != nil {
			single(p)
			continue
		}
		out[p.ID] = meterRead{snap: snap}
	}
	var orphans []string
	for name := range groups {
		// Ownership alone cannot prove purpose: old probes and removed configuration
		// entries used identical IDs. Report every candidate; never delete on a poll.
		if !known[name] {
			orphans = append(orphans, name)
		}
	}
	sort.Strings(orphans)
	return out, orphans
}
func (m nftMeter) RenewAll(ps []Profile) error {
	var s strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&s, "flush set inet %s alive\nadd element inet %s alive { %d timeout 15s }\n", m.table(p), m.table(p), p.Port)
	}
	return nftApply(s.String())
}
func (m nftMeter) isProbe(name string) bool {
	return strings.HasPrefix(name, m.prefix()+"probe_") && idPattern.MatchString(strings.TrimPrefix(name, m.prefix()+"probe_"))
}
func (m nftMeter) DeleteTables(names []string) error {
	var s strings.Builder
	for _, name := range names {
		if !m.isProbe(name) {
			return fmt.Errorf("%s: 无法证明是安装探针，保留该表", name)
		}
		if _, e := m.Read(Profile{ID: strings.TrimPrefix(name, m.prefix())}); e != nil {
			return e
		}
		s.WriteString("delete table inet " + name + "\n")
	}
	if s.Len() == 0 {
		return nil
	}
	return nftApply(s.String())
}

// Destructive mutations of an existing table must first prove ownership. A missing JSON
// comment uses exactly the same fallback as Read/ReadAll, including during repair.
func (m nftMeter) checkExisting(p Profile) error {
	b, e := nftRun("", "-j", "list", "table", "inet", m.table(p))
	if e != nil {
		return e
	}
	entries, e := decodeNFT(b)
	if e != nil {
		return fmt.Errorf("%s: nft JSON: %w", m.table(p), e)
	}
	return m.attestTable(m.table(p), entries)
}
func (m nftMeter) Replace(p Profile, r TrafficRecord) (string, error) {
	name := m.table(p)
	e := m.checkExisting(p)
	if e != nil && !errors.Is(e, errMeterMissing) {
		return "", e
	}
	// Atomic replacement is allowed only after attestation; creation is exclusive.
	script := "create table inet " + name + " { comment \"Rout traffic v1\"; }\n"
	if e == nil {
		script = "delete table inet " + name + "\n" + script
	}
	if e = nftApply(script + m.tableRules(p, r)); e != nil {
		return "", e
	}
	snap, e := m.Read(p)
	return snap.Hash, e
}
func (m nftMeter) tableRules(p Profile, r TrafficRecord) string {
	name := m.table(p)
	s := fmt.Sprintf("table inet %s {\ncomment \"Rout traffic v1\";\ncounter up { packets 0 bytes %d; }\ncounter down { packets 0 bytes %d; }\n", name, r.RawUp, r.RawDown)
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
	return s
}

// The deferred deletion is registered immediately after exclusive creation, before
// any read/parse. It deliberately bypasses attestation: only this invocation can
// have created this unpredictable name, even if subsequent reads lose permission.
func (m nftMeter) probe(p Profile) (err error) {
	if !m.isProbe(m.table(p)) {
		return errors.New("安装探针名称无效")
	}
	if err = nftApply("create table inet " + m.table(p) + " { comment \"Rout traffic v1\"; }\n" + m.tableRules(p, TrafficRecord{})); err != nil {
		return err
	}
	defer func() {
		if e := nftApply("delete table inet " + m.table(p) + "\n"); e != nil {
			err = errors.Join(err, fmt.Errorf("清理本次安装探针 %s 失败: %w", m.table(p), e))
		}
	}()
	_, err = m.Read(p)
	return err
}
func (m nftMeter) Freeze(p Profile) error {
	if e := m.checkExisting(p); e != nil {
		return e
	}
	name := m.table(p)
	return nftApply("flush chain inet " + name + " up_gate\nadd rule inet " + name + " up_gate drop\nflush chain inet " + name + " down_gate\nadd rule inet " + name + " down_gate drop\n")
}
func (m nftMeter) Renew(p Profile) error {
	// Flush + add is one atomic transaction, hence no lease gap.
	return nftApply(fmt.Sprintf("flush set inet %s alive\nadd element inet %s alive { %d timeout 15s }\n", m.table(p), m.table(p), p.Port))
}
func (m nftMeter) Delete(p Profile) error {
	if e := m.checkExisting(p); e != nil {
		return e
	}
	return nftApply("delete table inet " + m.table(p) + "\n")
}
