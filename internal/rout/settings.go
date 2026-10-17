package rout

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Settings struct {
	Language string       `json:"language,omitempty"`
	Server   *ServerSetup `json:"server,omitempty"`
	// Automatic pre-change backups to keep; 0 means the default (20).
	BackupKeep int `json:"backup_keep,omitempty"`
	// Last relay destination type chosen ("local"/"remote"), offered as the default.
	RelayMode string `json:"relay_mode,omitempty"`
}
type ServerSetup struct {
	NAT         bool   `json:"nat"`
	PublicHost  string `json:"public_host"`
	Listen      string `json:"listen"`
	LocalStart  int    `json:"local_start,omitempty"`
	LocalEnd    int    `json:"local_end,omitempty"`
	PublicStart int    `json:"public_start,omitempty"`
	Network     string `json:"network,omitempty"`
}

func (s ServerSetup) Validate() error {
	if !validHost(s.PublicHost) || net.ParseIP(s.Listen) == nil {
		return errors.New("监听地址或公网地址无效")
	}
	if s.NAT {
		if !validPort(s.LocalStart) || !validPort(s.LocalEnd) || s.LocalEnd < s.LocalStart || !validPort(s.PublicStart) || !validPort(s.PublicStart+s.LocalEnd-s.LocalStart) {
			return errors.New("NAT 端口范围或映射无效")
		}
		if s.Network != "tcp" && s.Network != "udp" && s.Network != "both" {
			return errors.New("NAT 网络类型无效")
		}
	}
	return nil
}
func (a *App) LoadSettings() (Settings, error) {
	var s Settings
	b, e := os.ReadFile(filepath.Join(a.Home, "settings.json"))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, errors.New("设置文件无效")
	}
	if s.Language != "" && s.Language != "zh-CN" && s.Language != "en" {
		return s, errors.New("语言设置无效")
	}
	if s.Server != nil {
		if e = s.Server.Validate(); e != nil {
			return s, e
		}
	}
	if s.BackupKeep < 0 || s.BackupKeep > 1000 {
		return s, errors.New("备份保留数量无效")
	}
	return s, nil
}
func (a *App) SaveSettings(s Settings) error {
	if s.Language != "en" && s.Language != "zh-CN" {
		return errors.New("语言设置无效")
	}
	if s.Server != nil {
		if e := s.Server.Validate(); e != nil {
			return e
		}
	}
	if s.BackupKeep < 0 || s.BackupKeep > 1000 {
		return errors.New("备份保留数量无效")
	}
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	b, e := JSON(s)
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(a.Home, "settings.json"), b, 0600)
}
func ParsePortRange(v string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, errors.New("端口范围格式应为 20000-20019 或单个端口")
	}
	start, e := strconv.Atoi(parts[0])
	if e != nil || !validPort(start) {
		return 0, 0, errors.New("端口应为 1–65535")
	}
	end := start
	if len(parts) == 2 {
		end, e = strconv.Atoi(parts[1])
		if e != nil || !validPort(end) || end < start {
			return 0, 0, errors.New("端口范围无效")
		}
	}
	return start, end, nil
}
func sharesNetwork(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
func PlanPort(p Profile, setup ServerSetup, s State) (Profile, error) {
	if e := setup.Validate(); e != nil {
		return p, e
	}
	p.NAT = setup.NAT
	p.PublicHost = setup.PublicHost
	p.Listen = setup.Listen
	if setup.NAT && p.Protocol == "ss" && setup.Network != "both" {
		p.Network = setup.Network
	}
	if setup.NAT && setup.Network != "both" {
		for _, n := range p.Networks() {
			if n != setup.Network {
				return p, errors.New("所选协议需要的网络不在 NAT 允许范围内")
			}
		}
	}
	attempts := 512
	if setup.NAT {
		attempts = setup.LocalEnd - setup.LocalStart + 1
	}
	for i := 0; i < attempts; i++ {
		port := setup.LocalStart + i
		if !setup.NAT {
			var e error
			port, e = freePort()
			if e != nil {
				return p, e
			}
		}
		p.Port = port
		p.PublicPort = port
		if setup.NAT {
			p.PublicPort = setup.PublicStart + port - setup.LocalStart
		}
		reserved := false
		for _, old := range s.Profiles {
			if old.Port == port && old.ID != p.ID && sharesNetwork(old.Networks(), p.Networks()) {
				reserved = true
				break
			}
		}
		if !reserved && CheckAvailable(p) == nil {
			return p, nil
		}
	}
	return p, errors.New("没有可用端口，请检查分配范围、UDP 权限和已有节点")
}
func AllowedPort(p Profile, setup ServerSetup) bool {
	if !setup.NAT {
		return p.PublicPort == p.Port
	}
	if p.Port < setup.LocalStart || p.Port > setup.LocalEnd || p.PublicPort != setup.PublicStart+p.Port-setup.LocalStart {
		return false
	}
	for _, n := range p.Networks() {
		if setup.Network != "both" && setup.Network != n {
			return false
		}
	}
	return true
}
