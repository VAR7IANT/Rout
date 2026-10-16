package rout

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"
)

type App struct{ Home, BinDir, ServiceMode string }

func DefaultApp() *App                     { return &App{Home: "/etc/rout", BinDir: "/opt/rout/bin", ServiceMode: "auto"} }
func itoa(n int) string                    { return strconv.Itoa(n) }
func (a *App) profileDir(id string) string { return filepath.Join(a.Home, "profiles", id) }
func (a *App) engineName(p Profile) string {
	if p.Kind == "relay" {
		return "gost"
	}
	return "sing-box"
}
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".rout-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e == nil {
		defer d.Close()
		e = d.Sync()
	}
	return e
}
func (a *App) Load() (State, error) {
	b, e := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if os.IsNotExist(e) {
		return State{Schema: 1, Profiles: []Profile{}}, nil
	}
	if e != nil {
		return State{}, e
	}
	return DecodeState(b)
}
func DecodeState(b []byte) (State, error) {
	var s State
	if len(b) > 16<<20 {
		return s, errors.New("配置文件过大")
	}
	if e := json.Unmarshal(b, &s); e != nil {
		return s, errors.New("配置 JSON 无效")
	}
	return s, s.Validate()
}
func (a *App) lock() (func(), error) {
	if e := os.MkdirAll(a.Home, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(a.Home, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("另一个 rout 正在修改配置，请稍后重试")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func Find(s State, id string) (Profile, error) {
	for _, p := range s.Profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, errors.New("找不到线路 ID")
}
func replace(s State, p Profile) State {
	out := State{Schema: s.Schema, Profiles: append([]Profile(nil), s.Profiles...)}
	for i := range out.Profiles {
		if out.Profiles[i].ID == p.ID {
			out.Profiles[i] = p
			return out
		}
	}
	out.Profiles = append(out.Profiles, p)
	return out
}
func removeProfile(s State, id string) State {
	out := State{Schema: 1, Profiles: []Profile{}}
	for _, p := range s.Profiles {
		if p.ID != id {
			out.Profiles = append(out.Profiles, p)
		}
	}
	return out
}

func CheckAvailable(p Profile) error {
	for _, n := range p.Networks() {
		addr := net.JoinHostPort(p.Listen, itoa(p.Port))
		if n == "tcp" {
			l, e := net.Listen("tcp", addr)
			if e != nil {
				return fmt.Errorf("TCP %d 不可用：%w", p.Port, e)
			}
			l.Close()
		} else {
			l, e := net.ListenPacket("udp", addr)
			if e != nil {
				return fmt.Errorf("UDP %d 不可用：%w", p.Port, e)
			}
			l.Close()
		}
	}
	return nil
}
func (a *App) writeProfile(p Profile) error {
	dir := a.profileDir(p.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if p.CertPEM != "" {
		if e := AtomicWrite(filepath.Join(dir, "tls.crt"), []byte(p.CertPEM), 0600); e != nil {
			return e
		}
		if e := AtomicWrite(filepath.Join(dir, "tls.key"), []byte(p.KeyPEM), 0600); e != nil {
			return e
		}
	}
	c, e := serverConfig(p, dir)
	if e != nil {
		return e
	}
	b, e := JSON(c)
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(dir, "config.json"), b, 0600)
}

// Commit checks configuration first and rolls state, generated files and services back together.
func (a *App) Commit(old, next State, force bool) error {
	if e := next.Validate(); e != nil {
		return e
	}
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	current, e := a.Load()
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(current, old) {
		return errors.New("配置已被其他操作修改，请重新打开菜单")
	}
	if _, e = a.serviceManager(); e != nil {
		return e
	}
	changed := map[string]bool{}
	for _, p := range next.Profiles {
		prev, err := Find(old, p.ID)
		if force || err != nil || !reflect.DeepEqual(prev, p) {
			changed[p.ID] = true
		}
		if p.Enabled && (err != nil || !prev.Enabled || p.Port != prev.Port || p.Listen != prev.Listen || !reflect.DeepEqual(p.Networks(), prev.Networks())) {
			if e := CheckAvailable(p); e != nil {
				return e
			}
		}
	}
	for _, p := range old.Profiles {
		if _, e := Find(next, p.ID); e != nil {
			changed[p.ID] = true
		}
	}
	for _, p := range next.Profiles {
		if changed[p.ID] {
			if e := p.Ready(); e != nil {
				return e
			}
			if e := a.EnsureEngine(a.engineName(p)); e != nil {
				return e
			}
		}
	}
	oldBytes, _ := JSON(old)
	if len(changed) > 0 {
		if e := AtomicWrite(filepath.Join(a.Home, "backups", time.Now().UTC().Format("20060102T150405.000000000")+".json"), oldBytes, 0600); e != nil {
			return e
		}
	}
	rollback := func(cause error) error {
		var failures []error
		for _, p := range next.Profiles {
			if !changed[p.ID] {
				continue
			}
			if prev, er := Find(old, p.ID); er == nil {
				if er = a.writeProfile(prev); er != nil {
					failures = append(failures, er)
				}
				if er = a.setService(prev, prev.Enabled); er != nil {
					failures = append(failures, er)
				}
			} else {
				if er := a.removeService(p); er != nil {
					failures = append(failures, er)
				}
				os.RemoveAll(a.profileDir(p.ID))
			}
		}
		for _, p := range old.Profiles {
			if changed[p.ID] {
				if _, er := Find(next, p.ID); er != nil {
					if er = a.writeProfile(p); er != nil {
						failures = append(failures, er)
					}
					if er = a.setService(p, p.Enabled); er != nil {
						failures = append(failures, er)
					}
				}
			}
		}
		if er := AtomicWrite(filepath.Join(a.Home, "state.json"), oldBytes, 0600); er != nil {
			failures = append(failures, er)
		}
		if len(failures) > 0 {
			return fmt.Errorf("操作失败：%w；恢复时还有错误：%v，请检查 rout status", cause, failures)
		}
		return fmt.Errorf("操作失败，已恢复原配置：%w", cause)
	}
	for _, p := range next.Profiles {
		if !changed[p.ID] {
			continue
		}
		if e := a.writeProfile(p); e != nil {
			return rollback(e)
		}
		if p.Kind == "node" {
			if e := a.checkConfig(filepath.Join(a.profileDir(p.ID), "config.json")); e != nil {
				return rollback(e)
			}
		}
	}
	// Stop removed entries before enabling replacements that may reuse their ports.
	for _, p := range old.Profiles {
		if _, er := Find(next, p.ID); er != nil {
			if e := a.removeService(p); e != nil {
				return rollback(e)
			}
		}
	}
	b, e := JSON(next)
	if e != nil {
		return rollback(e)
	}
	if e = AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		return rollback(e)
	}
	for _, p := range next.Profiles {
		if changed[p.ID] {
			if e := a.setService(p, p.Enabled); e != nil {
				return rollback(e)
			}
		}
	}
	for _, p := range old.Profiles {
		if _, er := Find(next, p.ID); er != nil {
			if e := os.RemoveAll(a.profileDir(p.ID)); e != nil {
				return e
			}
		}
	}
	return nil
}

func (a *App) Backup(path string) error {
	s, e := a.Load()
	if e != nil {
		return e
	}
	b, e := JSON(s)
	if e != nil {
		return e
	}
	return AtomicWrite(path, b, 0600)
}
func (a *App) Restore(path string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	next, e := DecodeState(b)
	if e != nil {
		return e
	}
	old, e := a.Load()
	if e != nil {
		return e
	}
	return a.Commit(old, next, true)
}
