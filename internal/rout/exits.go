package rout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type Exit struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Proxy Proxy  `json:"proxy"`
}

func (s State) Clone() State {
	out := s
	out.Profiles = append([]Profile{}, s.Profiles...)
	out.Exits = append([]Exit(nil), s.Exits...)
	if s.AI != nil {
		cp := s.AI.clone()
		out.AI = &cp
	}
	return out
}
func FindExit(s State, id string) (Exit, error) {
	for _, e := range s.Exits {
		if e.ID == id {
			return e, nil
		}
	}
	return Exit{}, errors.New("找不到出站代理")
}
func (s State) MigrateLegacyExits() State {
	out := s.Clone()
	for i, p := range out.Profiles {
		if p.Outbound == nil || p.ExitID != "" {
			continue
		}
		var id string
		for _, e := range out.Exits {
			if e.Proxy == *p.Outbound {
				id = e.ID
				break
			}
		}
		if id == "" {
			b, _ := json.Marshal(p.Outbound)
			h := sha256.Sum256(b)
			id = hex.EncodeToString(h[:6])
			for {
				if _, e := FindExit(out, id); e != nil {
					break
				}
				h = sha256.Sum256(h[:])
				id = hex.EncodeToString(h[:6])
			}
			name := strings.ToUpper(p.Outbound.Protocol) + "-" + p.Outbound.Host
			if len(name) > 160 {
				name = name[:147] + "-" + id
			}
			out.Exits = append(out.Exits, Exit{ID: id, Name: name, Proxy: *p.Outbound})
		}
		out.Profiles[i].ExitID = id
	}
	return out
}
func (s State) validateExits() error {
	ids := map[string]bool{}
	for _, e := range s.Exits {
		if !idPattern.MatchString(e.ID) || strings.TrimSpace(e.Name) == "" || len(e.Name) > 160 || strings.ContainsAny(e.Name, "\r\n\x00") {
			return errors.New("出站代理名称或 ID 无效")
		}
		if ids[e.ID] {
			return errors.New("出站代理 ID 重复")
		}
		ids[e.ID] = true
		if er := e.Proxy.Validate(); er != nil {
			return fmt.Errorf("%s: %w", e.Name, er)
		}
	}
	for _, p := range s.Profiles {
		if p.ExitID == "" {
			continue
		}
		e, err := FindExit(s, p.ExitID)
		if err != nil {
			return err
		}
		if p.Kind != "node" || p.Outbound == nil || !reflect.DeepEqual(*p.Outbound, e.Proxy) {
			return errors.New("节点引用的出站代理与配置不一致")
		}
	}
	return nil
}
func UpsertExit(s State, e Exit) State {
	out := s.Clone()
	found := false
	for i, v := range out.Exits {
		if v.ID == e.ID {
			out.Exits[i] = e
			found = true
			break
		}
	}
	if !found {
		out.Exits = append(out.Exits, e)
	}
	for i, p := range out.Profiles {
		if p.ExitID == e.ID {
			proxy := e.Proxy
			out.Profiles[i].Outbound = &proxy
		}
	}
	return out
}
func BindExit(s State, nodeID, exitID string) (State, error) {
	p, err := Find(s, nodeID)
	if err != nil {
		return s, err
	}
	if p.Kind != "node" {
		return s, errors.New("中转节点不使用出站代理；如需出站代理，请在目标节点上设置")
	}
	p.ExitID = exitID
	p.Outbound = nil
	if exitID != "" {
		e, err := FindExit(s, exitID)
		if err != nil {
			return s, err
		}
		proxy := e.Proxy
		p.Outbound = &proxy
	}
	return replace(s, p), nil
}
func DeleteExit(s State, id string) (State, error) {
	if _, e := FindExit(s, id); e != nil {
		return s, e
	}
	for _, p := range s.Profiles {
		if p.ExitID == id {
			return s, errors.New("出站代理仍被节点使用，请先改为其他出站或直连")
		}
	}
	if s.AI != nil && s.AI.AIOutboundID == id {
		return s, errors.New("出站代理正被 AI 智能分流用作 AI 出口，请先在 AI 智能分流中更换")
	}
	out := s.Clone()
	out.Exits = nil
	for _, e := range s.Exits {
		if e.ID != id {
			out.Exits = append(out.Exits, e)
		}
	}
	return out, nil
}
