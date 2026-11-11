package rout

import (
	"fmt"
	"strings"
)

// Surge subscription format (?format=surge).
//
// Surge reads a proxy list from a URL (an external policy group's policy-path) in the same
// syntax as its [Proxy] section, one proxy per line. Snell has no share link, so this is the
// only subscription format that can carry a Snell node. It lists exactly the nodes Rout can
// write a Surge line for (Snell today); every other node is left out with a diagnostic
// instead of being converted into something Surge would not understand.

// exportSurge resolves a subscription's local nodes into Surge proxy lines.
func (s State) exportSurge(sub Subscription) (lines []string, warnings []string) {
	byID := make(map[string]Profile, len(s.Profiles))
	for _, p := range s.Profiles {
		byID[p.ID] = p
	}
	taken := map[string]bool{}
	for _, id := range sub.localIDs() {
		p, ok := byID[id]
		switch {
		case !ok:
			warnings = append(warnings, fmt.Sprintf("节点 %s 已删除，已跳过", id))
			continue
		case !p.Enabled:
			warnings = append(warnings, fmt.Sprintf("节点 %s 已停用，已跳过", p.Name))
			continue
		case !p.snellNode():
			warnings = append(warnings, fmt.Sprintf("节点 %s 无法生成 Surge 配置：Surge 格式目前只包含 Snell 节点", p.Name))
			continue
		}
		q := p
		q.Name = uniqueSurgeName(taken, surgeName(p.Name))
		line, e := q.SurgeLine(p.PublicHost, p.PublicPort)
		if e != nil {
			warnings = append(warnings, fmt.Sprintf("节点 %s 无法生成 Surge 配置：%s", p.Name, e.Error()))
			continue
		}
		lines = append(lines, line)
	}
	return lines, warnings
}

// uniqueSurgeName keeps policy names distinct inside one list (Surge requires it, and
// sanitising a name can make two different names equal).
func uniqueSurgeName(taken map[string]bool, name string) string {
	candidate := name
	for i := 2; taken[strings.ToLower(candidate)]; i++ {
		candidate = fmt.Sprintf("%s %d", name, i)
	}
	taken[strings.ToLower(candidate)] = true
	return candidate
}

func renderSurge(lines []string) string { return strings.Join(lines, "\n") + "\n" }
