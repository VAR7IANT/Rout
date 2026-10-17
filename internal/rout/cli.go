package rout

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Global flags are accepted before or after the command (rout list --lang en).
var valueFlags = map[string]bool{"home": true, "bin-dir": true, "service": true, "lang": true}

func splitFlags(args []string) (flags, rest []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return flags, append(rest, args[i+1:]...)
		}
		name := strings.TrimLeft(arg, "-")
		if strings.HasPrefix(arg, "-") && name != "" && name != arg {
			key, _, inline := strings.Cut(name, "=")
			if valueFlags[key] {
				flags = append(flags, arg)
				if !inline && i+1 < len(args) {
					flags = append(flags, args[i+1])
					i++
				}
				continue
			}
			if key == "h" || key == "help" {
				flags = append(flags, arg)
				continue
			}
		}
		rest = append(rest, arg)
	}
	return flags, rest
}

var helpLines = [][2]string{
	{"rout", "交互式菜单"},
	{"rout list", "全部节点、状态与完整分享链接"},
	{"rout status", "服务运行状态"},
	{"rout doctor [--fix]", "只读诊断；--fix 逐项确认后修复"},
	{"rout test ID", "测试本地入口、协议和出口（IPv4/IPv6）"},
	{"rout export ID [FILE]", "输出分享链接，或保存 sing-box 客户端配置"},
	{"rout export all [FILE]", "输出全部分享链接，或保存到文件"},
	{"rout copy ID", "输出链接并请求终端复制"},
	{"rout restart|on|off|delete|logs ID", "管理单个节点"},
	{"rout exits", "出口管理"},
	{"rout traffic", "全部节点流量"},
	{"rout traffic show|manage ID", "查看或管理节点流量与限额"},
	{"rout traffic recover ID", "保留已知用量并恢复计量故障暂停的节点"},
	{"rout traffic install", "安装或更新流量监控（不重启现有节点）"},
	{"rout cert [ID]", "查看 HY2/TUIC 证书有效期"},
	{"rout cert renew ID", "重新生成自签证书（客户端需重新导入）"},
	{"rout apply", "校验并重新应用全部节点"},
	{"rout backup|restore FILE", "备份或恢复配置"},
	{"rout settings", "语言、服务器默认设置与备份保留数量"},
	{"rout engines", "下载并校验固定版本内核"},
	{"rout update", "更新 Rout（拒绝降级）"},
	{"rout uninstall", "卸载 Rout"},
	{"rout version", "版本"},
}

func (a *App) help() {
	fmt.Println(a.T("用法："))
	for _, line := range helpLines {
		fmt.Printf("  %s  %s\n", pad(line[0], 38), a.T(line[1]))
	}
	fmt.Println()
	fmt.Println(a.T("全局选项：--lang en|zh-CN  --home DIR  --bin-dir DIR  --service auto|none（仅测试）"))
}
func Run(args []string) (result error) {
	a := DefaultApp()
	defer func() { result = FormatError(a.Language, result) }()
	var language string
	flagArgs, args := splitFlags(args)
	flags := flag.NewFlagSet("rout", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&a.Home, "home", a.Home, "configuration directory")
	flags.StringVar(&a.BinDir, "bin-dir", a.BinDir, "engine directory")
	flags.StringVar(&a.ServiceMode, "service", "auto", "auto or none (test-only)")
	flags.StringVar(&language, "lang", "", "en or zh-CN (override saved language)")
	if e := flags.Parse(flagArgs); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			args = []string{"help"}
		} else {
			return e
		}
	}
	if language != "" {
		if language != "en" && language != "zh-CN" {
			return errors.New("语言设置无效")
		}
		a.Language = language
	}
	cmd := "menu"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd == "version" {
		fmt.Println("rout " + Version)
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
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		if settings, er := a.LoadSettings(); er == nil && language == "" {
			a.Language = settings.Language
		}
		a.help()
		return nil
	}
	settings, e := a.LoadSettings()
	if e != nil {
		return e
	}
	a.Language = settings.Language
	a.BackupKeep = settings.BackupKeep
	if language != "" {
		a.Language = language
	}
	readOnly := cmd == "list" || cmd == "status" || cmd == "export" || cmd == "copy" || cmd == "doctor" && !contains(args, "--fix")
	if os.Geteuid() != 0 && a.ServiceMode != "none" && !readOnly {
		return errors.New("请使用 sudo rout 或 root 运行")
	}
	u := &UI{a: a, in: bufio.NewReader(os.Stdin)}
	switch cmd {
	case "traffic":
		return u.trafficCommand(args)
	case "menu":
		return u.mainMenu()
	case "doctor":
		return u.doctor(contains(args, "--fix"))
	case "exits":
		if e := u.initLanguage(false); e != nil {
			return e
		}
		return u.exits()
	case "settings":
		if e := u.initLanguage(false); e != nil {
			return e
		}
		return u.settings()
	case "update":
		return SelfUpdate(a.Language)
	case "engines":
		for _, name := range []string{"sing-box", "gost"} {
			if e := a.EnsureEngine(name); e != nil {
				return e
			}
		}
		return nil
	case "backup", "restore":
		if len(args) != 2 {
			return errors.New("请指定备份文件路径")
		}
		if cmd == "backup" {
			return a.Backup(args[1])
		}
		return a.Restore(args[1])
	case "uninstall":
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
			line := fmt.Sprintf("%s  %s  %s", p.ID, pad(p.Name, 24), a.Running(p))
			if days, ok := p.CertificateDays(time.Now()); ok {
				line += "  " + fmt.Sprintf(a.T("证书剩余 %d 天"), days)
			}
			fmt.Println(line)
		}
		return nil
	case "apply":
		return a.Commit(s, s, true)
	case "cert":
		return u.certCommand(s, args)
	case "export":
		if len(args) >= 2 && args[1] == "all" {
			links := AllLinks(s)
			if len(args) == 3 {
				return AtomicWrite(args[2], []byte(links), 0600)
			}
			fmt.Print(links)
			return nil
		}
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
func (u *UI) trafficCommand(args []string) error {
	a := u.a
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
	}
	if len(args) != 3 {
		return errors.New("用法：rout traffic [install|show ID|manage ID|recover ID]")
	}
	if args[1] == "guard" {
		return a.TrafficGuard(args[2])
	}
	s, e := a.Load()
	if e != nil {
		return e
	}
	p, e := Find(s, args[2])
	if e != nil {
		return e
	}
	switch args[1] {
	case "show":
		return u.showTraffic(p)
	case "manage":
		if e = u.initLanguage(false); e != nil {
			return e
		}
		return u.trafficManage(p)
	case "recover":
		return u.recoverTraffic(p)
	}
	return errors.New("用法：rout traffic [install|show ID|manage ID|recover ID]")
}

// certCommand lists certificate validity, or regenerates one with confirmation.
func (u *UI) certCommand(s State, args []string) error {
	if len(args) == 3 && args[1] == "renew" {
		p, e := Find(s, args[2])
		if e != nil {
			return e
		}
		if _, ok := p.CertificateExpiry(); !ok {
			return errors.New("该节点未使用文件证书")
		}
		u.warn("新证书的指纹会改变：所有客户端必须重新导入链接或客户端配置")
		if !u.yes(fmt.Sprintf(u.a.T("为 %s 重新生成自签证书"), p.Name), false) {
			return u.err
		}
		if p, e = RegenerateCertificate(p); e != nil {
			return e
		}
		if e = u.a.Commit(s, replace(s, p), false); e != nil {
			return e
		}
		u.good("证书已更新；请重新导入以下链接")
		return u.copy(p)
	}
	if len(args) > 2 {
		return errors.New("用法：rout cert [ID] 或 rout cert renew ID")
	}
	found := false
	for _, p := range s.Profiles {
		if len(args) == 2 && p.ID != args[1] {
			continue
		}
		end, ok := p.CertificateExpiry()
		if !ok {
			continue
		}
		found = true
		days, _ := p.CertificateDays(time.Now())
		u.printf("%s [%s]  %s  到期 %s（剩余 %d 天）\n", p.Name, p.ID, p.SNI, end.Format("2006-01-02"), days)
	}
	if !found {
		u.say("没有使用证书的 HY2/TUIC 节点")
	}
	return nil
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
