package rout

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func Run(args []string) (result error) {
	a := DefaultApp()
	defer func() { result = FormatError(a.Language, result) }()
	var language string
	flags := flag.NewFlagSet("rout", flag.ContinueOnError)
	flags.StringVar(&a.Home, "home", a.Home, "configuration directory")
	flags.StringVar(&a.BinDir, "bin-dir", a.BinDir, "engine directory")
	flags.StringVar(&a.ServiceMode, "service", "auto", "auto or none (test-only)")
	flags.StringVar(&language, "lang", "", "en or zh-CN (override saved language)")
	if e := flags.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if language != "" {
		if language != "en" && language != "zh-CN" {
			return errors.New("语言设置无效")
		}
		a.Language = language
	}
	args = flags.Args()
	cmd := "menu"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd == "version" {
		fmt.Println("rout " + Version)
		return nil
	}
	if cmd == "help" {
		fmt.Println("rout [--lang en|zh-CN --home DIR --bin-dir DIR --service auto|none] [menu|list|status|test ID|copy ID|export ID [FILE]|restart ID|on ID|off ID|delete ID|logs ID|exits|settings|traffic [install|show ID|manage ID]|apply|backup FILE|restore FILE|engines|update|uninstall]")
		return nil
	}
	var e error
	a.Home, e = filepath.Abs(a.Home)
	if e != nil {
		return e
	}
	a.BinDir, e = filepath.Abs(a.BinDir)
	if e != nil {
		return e
	}
	if a.Home == "/" || a.BinDir == "/" || a.Home == a.BinDir {
		return errors.New("配置和内核目录必须是独立专用目录")
	}
	settings, e := a.LoadSettings()
	if e != nil {
		return e
	}
	a.Language = settings.Language
	if language != "" {
		if language != "en" && language != "zh-CN" {
			return errors.New("语言设置无效")
		}
		a.Language = language
	}
	readOnly := cmd == "list" || cmd == "status" || cmd == "export" || cmd == "copy"
	if os.Geteuid() != 0 && a.ServiceMode != "none" && !readOnly {
		return errors.New("请使用 sudo rout 或 root 运行")
	}
	u := &UI{a: a, in: bufio.NewReader(os.Stdin)}
	if cmd == "traffic" {
		if len(args) < 2 {
			s, e := a.Load()
			if e != nil {
				return e
			}
			for _, p := range s.Profiles {
				if e = u.showTraffic(p); e != nil {
					return e
				}
			}
			return nil
		}
		switch args[1] {
		case "install":
			return a.InstallTraffic()
		case "run":
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return a.RunTraffic(ctx)
		case "sync":
			return a.TrafficSync(time.Now(), false)
		case "guard":
			if len(args) != 3 {
				return errors.New("命令需要线路 ID，请运行 rout list")
			}
			return a.TrafficGuard(args[2])
		case "show", "manage":
			if len(args) != 3 {
				return errors.New("命令需要线路 ID，请运行 rout list")
			}
			s, e := a.Load()
			if e != nil {
				return e
			}
			p, e := Find(s, args[2])
			if e != nil {
				return e
			}
			if args[1] == "show" {
				return u.showTraffic(p)
			}
			if e = u.initLanguage(false); e != nil {
				return e
			}
			return u.trafficManage(p)
		}
		return errors.New("用法：rout traffic [install|show ID|manage ID]")
	}
	if cmd == "menu" {
		return u.menu()
	}
	if cmd == "exits" {
		if e := u.initLanguage(false); e != nil {
			return e
		}
		return u.exits()
	}
	if cmd == "settings" {
		if e := u.initLanguage(false); e != nil {
			return e
		}
		return u.settings()
	}
	if cmd == "update" {
		return SelfUpdate(a.Language)
	}
	if cmd == "engines" {
		for _, name := range []string{"sing-box", "gost"} {
			if e := a.EnsureEngine(name); e != nil {
				return e
			}
		}
		return nil
	}
	if cmd == "backup" || cmd == "restore" {
		if len(args) != 2 {
			return errors.New("请指定备份文件路径")
		}
		if cmd == "backup" {
			return a.Backup(args[1])
		}
		return a.Restore(args[1])
	}
	if cmd == "uninstall" {
		if !u.yes("卸载所有 Rout 配置、服务和程序", false) {
			return u.err
		}
		return a.Uninstall()
	}
	s, e := a.Load()
	if e != nil {
		return e
	}
	switch cmd {
	case "list":
		u.list(s)
		return nil
	case "status":
		for _, p := range s.Profiles {
			fmt.Printf("%s  %s  %s\n", p.ID, p.Name, a.Running(p))
		}
		return nil
	case "apply":
		return a.Commit(s, s, true)
	}
	if len(args) < 2 {
		return errors.New("命令需要线路 ID，请运行 rout list")
	}
	p, e := Find(s, args[1])
	if e != nil {
		return e
	}
	switch cmd {
	case "restart":
		return a.Restart(p.ID)
	case "copy":
		return u.copy(p)
	case "test":
		return a.Probe(p)
	case "export":
		if len(args) == 2 {
			uri, e := p.URI()
			if e == nil {
				fmt.Println(uri)
			}
			return e
		}
		if len(args) != 3 {
			return errors.New("用法：rout export ID [客户端配置文件]")
		}
		c, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
		if e != nil {
			return e
		}
		b, e := JSON(c)
		if e != nil {
			return e
		}
		return AtomicWrite(args[2], b, 0600)
	case "on", "off":
		p.Enabled = cmd == "on"
		return a.Commit(s, replace(s, p), false)
	case "delete":
		if !u.yes(fmt.Sprintf(a.T("删除 %s"), p.Name), false) {
			return u.err
		}
		return a.Commit(s, removeProfile(s, p.ID), false)
	case "logs":
		return a.Logs(p)
	}
	return errors.New("未知命令，请运行 rout help")
}

func (a *App) Uninstall() error {
	if a.Home != "/etc/rout" || a.BinDir != "/opt/rout/bin" {
		return errors.New("自定义目录模式不执行自动卸载，请自行删除专用目录")
	}
	s, e := a.Load()
	if e != nil {
		return e
	}
	if e = a.Commit(s, State{Schema: 1, Profiles: []Profile{}}, false); e != nil {
		return e
	}
	if e = a.removeTrafficMonitor(); e != nil {
		return e
	}
	if e = os.RemoveAll(a.Home); e != nil {
		return e
	}
	if e = os.RemoveAll(a.BinDir); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		return e
	}
	if exe == "/usr/local/bin/rout" {
		if e = os.Remove(exe); e != nil {
			return e
		}
	}
	a.say("Rout 已卸载")
	return nil
}
